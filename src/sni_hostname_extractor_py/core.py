"""Core parsing logic for TLS ClientHello SNI extraction.

We operate on the post-TCP-segment byte stream: the full TLS record
record_layer, optional IP/TCP headers are not handled. Given a complete
ClientHello we walk the record and handshake layers, skip the session ID,
skip cipher suites, skip compression methods, walk the extensions, and
return the hostname bytes from the server_name extension.

The function is deliberately stateless: no sockets, no buffering, no
partial reassembly. If a caller has fragmented data they must coalesce it
first. This keeps the interface a pure function of bytes → str | None and
makes the behaviour trivially testable.
"""

from __future__ import annotations

from typing import Optional


class SNIExtractionError(Exception):
    """Raised when the bytes do not form a recognizable ClientHello.

    The message carries a short, human-readable reason. We raise rather
    than return a sentinel because a malformed capture is genuinely an
    error: callers inspecting packet captures almost always want to know
    *why* extraction failed, not just that it did.
    """


def _u16(data: bytes, offset: int) -> int:
    """Read one big-endian unsigned 16-bit integer at offset."""
    return (data[offset] << 8) | data[offset + 1]


def _u24(data: bytes, offset: int) -> int:
    """Read one big-endian unsigned 24-bit integer at offset."""
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


def _check_len(data: bytes, needed: int, why: str) -> None:
    if len(data) < needed:
        raise SNIExtractionError(
            f"truncated input: need {needed} bytes for {why}, have {len(data)}"
        )


def extract_sni(data: bytes) -> Optional[str]:
    """Extract the SNI hostname from a TLS ClientHello record.

    Args:
        data: The complete bytes of a single TLS record layer message
            whose handshake type is ClientHello (content type 22,
            handshake type 1).

    Returns:
        The hostname as a lowercase ASCII ``str``, or ``None`` if the
        ClientHello is well-formed but carries no server_name extension.

    Raises:
        SNIExtractionError: If the bytes cannot be parsed as a ClientHello
            record, or if a length field lies and the structure would walk
            off the end of the buffer.

    Notes:
        - Only the host_name variant of the SNI list is honoured. RFC 6066
          defines only that variant; other codepoints, if present, are
          skipped because there is nothing useful to do with them here.
        - Only the first host_name entry is returned. RFC 6066 allows at
          most one, so a second one indicates a buggy or hostile client.
          We raise rather than pick one arbitrarily.
        - IDN names are returned as their wire form (Punycode A-labels).
          Converting to a Unicode U-label is a presentation concern that
          belongs to the caller; doing it here would force a dependency on
          encodings.idna and an opinion on ToASCII/ToUnicode edge cases.
        - The hostname is lowercased. DNS comparison is case-insensitive and
          downstream lookups expect the canonical form.
    """
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise SNIExtractionError(
            f"expected bytes-like input, got {type(data).__name__}"
        )

    data = bytes(data)  # so indexing yields ints and slicing yields bytes
    _check_len(data, 5, "TLS record header")
    if data[0] != 0x16:
        raise SNIExtractionError(
            f"not a TLS handshake record: content_type=0x{data[0]:02x}, expected 0x16"
        )

    # TLS 1.0–1.2 use 0x0301..0x0303. TLS 1.3 negotiates 1.2 on the wire.
    # We are not strict about the version here because some clients
    # (notably GREASE-enabled ones) send surprising values in record
    # layer version and we do not want to reject a real ClientHello over
    # that. The handshake layer version is what matters semantically.
    rec_len = _u16(data, 3)
    # The record body must be present in full. We do not attempt to
    # reassemble: a truncated capture is treated as an error.
    _check_len(data, 5 + rec_len, "TLS record body")
    if rec_len < 4:
        raise SNIExtractionError(
            f"record body too small for a handshake header: {rec_len} bytes"
        )

    pos = 5
    hs_type = data[pos]
    if hs_type != 0x01:
        raise SNIExtractionError(
            f"not a ClientHello: handshake_type=0x{hs_type:02x}, expected 0x01"
        )
    hs_len = _u24(data, pos + 1)
    # hs_len counts bytes after the 4-byte handshake header.
    hs_end = pos + 4 + hs_len
    if hs_end > 5 + rec_len:
        raise SNIExtractionError(
            "handshake length exceeds record body: "
            f"hs_len={hs_len}, available={5 + rec_len - (pos + 4)}"
        )
    pos += 4

    # legacy_version (2 bytes) + random (32 bytes)
    _check_len(data, pos + 34, "version+random")
    if pos + 34 > hs_end:
        raise SNIExtractionError("handshake body truncated before session_id")
    pos += 34

    # legacy_session_id: 1-byte length, then that many bytes.
    _check_len(data, pos + 1, "session_id length")
    if pos + 1 > hs_end:
        raise SNIExtractionError("session_id length runs past handshake body")
    sid_len = data[pos]
    pos += 1
    _check_len(data, pos + sid_len, "session_id")
    if pos + sid_len > hs_end:
        raise SNIExtractionError("session_id runs past handshake body")
    pos += sid_len

    # cipher_suites: 2-byte length, then that many 2-byte suites.
    _check_len(data, pos + 2, "cipher_suites length")
    if pos + 2 > hs_end:
        raise SNIExtractionError("cipher_suites length runs past handshake body")
    cs_len = _u16(data, pos)
    if cs_len % 2 != 0:
        raise SNIExtractionError(
            f"cipher_suites length must be even, got {cs_len}"
        )
    pos += 2
    _check_len(data, pos + cs_len, "cipher_suites")
    if pos + cs_len > hs_end:
        raise SNIExtractionError("cipher_suites runs past handshake body")
    pos += cs_len

    # legacy_compression_methods: 1-byte length, then that many bytes.
    _check_len(data, pos + 1, "compression_methods length")
    if pos + 1 > hs_end:
        raise SNIExtractionError("compression_methods length past handshake body")
    cm_len = data[pos]
    pos += 1
    _check_len(data, pos + cm_len, "compression_methods")
    if pos + cm_len > hs_end:
        raise SNIExtractionError("compression_methods past handshake body")
    pos += cm_len

    # extensions: 2-byte total length, then that many bytes of extension
    # records. May be absent entirely (ClientHello with zero extensions).
    if pos == hs_end:
        return None
    if pos + 2 > hs_end:
        raise SNIExtractionError("extensions length past handshake body")
    ext_total = _u16(data, pos)
    pos += 2
    ext_end = pos + ext_total
    if ext_end > hs_end:
        raise SNIExtractionError(
            "extensions length runs past handshake body: "
            f"ext_total={ext_total}, remaining={hs_end - pos}"
        )

    while pos + 4 <= ext_end:
        ext_type = _u16(data, pos)
        ext_len = _u16(data, pos + 2)
        pos += 4
        if pos + ext_len > ext_end:
            raise SNIExtractionError(
                f"extension 0x{ext_type:04x} length {ext_len} runs past extensions"
            )
        if ext_type == 0x0000:
            return _parse_sni_extension(data, pos, ext_len)
        pos += ext_len

    return None


def _parse_sni_extension(data: bytes, start: int, length: int) -> str:
    """Parse a server_name extension body and return the first host_name."""
    if length < 2:
        raise SNIExtractionError("server_name extension too small for list length")
    pos = start
    list_len = _u16(data, pos)
    pos += 2
    if pos + list_len > start + length:
        raise SNIExtractionError(
            "server_name list length exceeds extension body: "
            f"list_len={list_len}, available={start + length - pos}"
        )
    list_end = pos + list_len

    found: Optional[str] = None
    while pos + 3 <= list_end:
        name_type = data[pos]
        name_len = _u16(data, pos + 1)
        pos += 3
        if pos + name_len > list_end:
            raise SNIExtractionError(
                f"server_name entry name_type={name_type} length {name_len} "
                "runs past list"
            )
        if name_type != 0x00:
            # Non-host_name entries are skipped silently; RFC 6066 only
            # defines codepoint 0 and a client that sends another is
            # speculating. We do not fail because the spec does not forbid
            # unknown codepoints in the way it forbids two host_names.
            pos += name_len
            continue
        if found is not None:
            raise SNIExtractionError(
                "multiple host_name entries in server_name extension "
                "(RFC 6066 permits at most one)"
            )
        raw = data[pos : pos + name_len]
        pos += name_len
        # Reject embedded NULs: a hostname with a NUL would let an
        # attacker smuggle data past tools that treat the C-string form
        # as authoritative. We surface this as a hard error rather than
        # silently truncating, because silent truncation is how that
        # confusion attack works.
        if b"\x00" in raw:
            raise SNIExtractionError("hostname contains NUL byte")
        try:
            host = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SNIExtractionError(
                f"hostname is not valid ASCII: {exc}"
            ) from exc
        found = host.lower()

    if found is None:
        raise SNIExtractionError(
            "server_name extension present but contains no host_name entry"
        )
    return found
