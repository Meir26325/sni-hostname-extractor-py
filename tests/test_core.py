"""Unit tests for sni_hostname_extractor_py.core.extract_sni."""

from __future__ import annotations

import unittest

from sni_hostname_extractor_py import extract_sni, SNIExtractionError
from sni_hostname_extractor_py.core import _parse_sni_extension


def _record(handshake_body: bytes) -> bytes:
    """Wrap a handshake body in a TLS record header."""
    return bytes([0x16, 0x03, 0x01]) + len(handshake_body).to_bytes(2, "big") + handshake_body


def _clienthello(
    *,
    session_id: bytes = b"",
    cipher_suites: bytes = b"\x00\x2f",
    compression_methods: bytes = b"\x01\x00",
    extensions: bytes = b"",
    hs_version: bytes = b"\x03\x03",
) -> bytes:
    """Build a minimal but well-formed ClientHello handshake body."""
    random_bytes = b"\x00" * 32
    body = (
        hs_version
        + random_bytes
        + bytes([len(session_id)]) + session_id
        + len(cipher_suites).to_bytes(2, "big") + cipher_suites
        + bytes([len(compression_methods)]) + compression_methods
    )
    if extensions:
        body += len(extensions).to_bytes(2, "big") + extensions
    hs_header = bytes([0x01]) + len(body).to_bytes(3, "big")
    return _record(hs_header + body)


def _sni_ext(hostname: str) -> bytes:
    """Build a single-host server_name extension body (excl. ext header)."""
    raw = hostname.encode("ascii")
    name_entry = bytes([0x00]) + len(raw).to_bytes(2, "big") + raw
    return len(name_entry).to_bytes(2, "big") + name_entry


def _ext(ext_type: int, body: bytes) -> bytes:
    """Build a full extension record including its 4-byte header."""
    return ext_type.to_bytes(2, "big") + len(body).to_bytes(2, "big") + body


class HappyPathTests(unittest.TestCase):

    def test_extracts_simple_hostname(self):
        msg = _clienthello(extensions=_ext(0x0000, _sni_ext("example.org")))
        self.assertEqual(extract_sni(msg), "example.org")

    def test_lowercase_hostname(self):
        msg = _clienthello(extensions=_ext(0x0000, _sni_ext("ExAmPlE.ORG")))
        self.assertEqual(extract_sni(msg), "example.org")

    def test_multiple_extensions_sni_second(self):
        other = _ext(0x0010, b"\x00\x02ab")
        sni = _ext(0x0000, _sni_ext("api.example.org"))
        msg = _clienthello(extensions=other + sni)
        self.assertEqual(extract_sni(msg), "api.example.org")

    def test_bytearray_input(self):
        msg = bytearray(_clienthello(extensions=_ext(0x0000, _sni_ext("x.org"))))
        self.assertEqual(extract_sni(msg), "x.org")

    def test_memoryview_input(self):
        msg = memoryview(_clienthello(extensions=_ext(0x0000, _sni_ext("y.org"))))
        self.assertEqual(extract_sni(msg), "y.org")

    def test_trailing_garbage_ignored(self):
        msg = _clienthello(extensions=_ext(0x0000, _sni_ext("z.org")))
        # The record layer length bounds parsing, so bytes after the record
        # are simply not inspected.
        self.assertEqual(extract_sni(msg + b"\xff\xff\xff\xff"), "z.org")


class NoSniTests(unittest.TestCase):

    def test_no_extensions_returns_none(self):
        self.assertIsNone(extract_sni(_clienthello()))

    def test_extensions_without_sni_returns_none(self):
        exts = _ext(0x0010, b"\x00\x00") + _ext(0x000b, b"\x01")
        self.assertIsNone(extract_sni(_clienthello(extensions=exts)))


class MalformedInputTests(unittest.TestCase):

    def test_non_bytes_raises(self):
        with self.assertRaises(SNIExtractionError):
            extract_sni("not bytes")  # type: ignore[arg-type]

    def test_empty_input_raises(self):
        with self.assertRaises(SNIExtractionError):
            extract_sni(b"")

    def test_wrong_content_type_raises(self):
        # Application data (0x17) instead of handshake (0x16)
        bad = bytes([0x17, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00])
        with self.assertRaises(SNIExtractionError):
            extract_sni(bad)

    def test_wrong_handshake_type_raises(self):
        # ServerHello handshake type 0x02
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x00\x2f\x01\x00"
        hs = bytes([0x02]) + len(body).to_bytes(3, "big") + body
        with self.assertRaises(SNIExtractionError):
            extract_sni(_record(hs))

    def test_truncated_record_header_raises(self):
        with self.assertRaises(SNIExtractionError):
            extract_sni(b"\x16\x03\x01")

    def test_record_body_truncated_raises(self):
        msg = _clienthello(extensions=_ext(0x0000, _sni_ext("a.b")))
        # Claim more bytes than present
        bad = msg[:3] + (len(msg) - 2).to_bytes(2, "big") + msg[5:]
        with self.assertRaises(SNIExtractionError):
            extract_sni(bad)

    def test_extension_length_runs_past_handshake_raises(self):
        exts = _ext(0x0000, _sni_ext("c.d"))
        # Claim the extensions block is one byte longer than it is
        body_core = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
        )
        ext_field = (len(exts) + 1).to_bytes(2, "big") + exts
        body = body_core + ext_field
        hs = bytes([0x01]) + len(body).to_bytes(3, "big") + body
        with self.assertRaises(SNIExtractionError):
            extract_sni(_record(hs))

    def test_sni_list_length_runs_past_extension_raises(self):
        bad_body = b"\x00\x10" + b"\x00" * 4  # claims 16, has 4
        msg = _clienthello(extensions=_ext(0x0000, bad_body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_name_entry_runs_past_list_raises(self):
        bad_body = b"\x00\x04\x00\x00\xff"  # claims name len 255, has 0
        msg = _clienthello(extensions=_ext(0x0000, bad_body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_non_ascii_hostname_raises(self):
        raw = "café.org".encode("latin-1")
        bad_entry = bytes([0x00]) + len(raw).to_bytes(2, "big") + raw
        bad_body = len(bad_entry).to_bytes(2, "big") + bad_entry
        msg = _clienthello(extensions=_ext(0x0000, bad_body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_nul_in_hostname_raises(self):
        raw = b"evil.org\x00.evil.org"
        bad_entry = bytes([0x00]) + len(raw).to_bytes(2, "big") + raw
        bad_body = len(bad_entry).to_bytes(2, "big") + bad_entry
        msg = _clienthello(extensions=_ext(0x0000, bad_body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_multiple_host_name_entries_raises(self):
        raw1 = b"a.org"
        raw2 = b"b.org"
        entry1 = bytes([0x00]) + len(raw1).to_bytes(2, "big") + raw1
        entry2 = bytes([0x00]) + len(raw2).to_bytes(2, "big") + raw2
        body = (len(entry1 + entry2)).to_bytes(2, "big") + entry1 + entry2
        msg = _clienthello(extensions=_ext(0x0000, body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_sni_extension_without_host_name_raises(self):
        # name_type 0x01 is unknown; we skip it, then find no host_name
        raw = b"ignored"
        entry = bytes([0x01]) + len(raw).to_bytes(2, "big") + raw
        body = len(entry).to_bytes(2, "big") + entry
        msg = _clienthello(extensions=_ext(0x0000, body))
        with self.assertRaises(SNIExtractionError):
            extract_sni(msg)

    def test_session_id_truncated_raises(self):
        body = b"\x03\x03" + b"\x00" * 32 + bytes([0x10])  # sid len 16, no body
        hs = bytes([0x01]) + len(body).to_bytes(3, "big") + body
        with self.assertRaises(SNIExtractionError):
            extract_sni(_record(hs))

    def test_odd_cipher_suites_length_raises(self):
        body = (
            b"\x03\x03" + b"\x00" * 32 + b"\x00"  # session_id
            + b"\x00\x03\x00\x2f\xff"  # cs_len=3, odd
        )
        hs = bytes([0x01]) + len(body).to_bytes(3, "big") + body
        with self.assertRaises(SNIExtractionError):
            extract_sni(_record(hs))

    def test_record_too_small_for_handshake_header_raises(self):
        bad = bytes([0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00])
        with self.assertRaises(SNIExtractionError):
            extract_sni(bad)

    def test_handshake_length_exceeds_record_raises(self):
        body = b"\x03\x03" + b"\x00" * 32 + b"\x00\x00\x02\x00\x2f\x01\x00"
        hs = bytes([0x01]) + (len(body) + 10).to_bytes(3, "big") + body
        with self.assertRaises(SNIExtractionError):
            extract_sni(_record(hs))


class NonHostNameEntriesTests(unittest.TestCase):

    def test_non_host_name_entry_skipped_then_host_name_returned(self):
        raw_unknown = b"skip-me"
        unknown_entry = bytes([0x01]) + len(raw_unknown).to_bytes(2, "big") + raw_unknown
        raw_host = b"real.org"
        host_entry = bytes([0x00]) + len(raw_host).to_bytes(2, "big") + raw_host
        body = (
            len(unknown_entry + host_entry).to_bytes(2, "big")
            + unknown_entry
            + host_entry
        )
        msg = _clienthello(extensions=_ext(0x0000, body))
        self.assertEqual(extract_sni(msg), "real.org")


class HelperDirectTests(unittest.TestCase):

    def test_parse_sni_extension_empty_list_raises(self):
        with self.assertRaises(SNIExtractionError):
            _parse_sni_extension(b"\x00\x00", 0, 2)


if __name__ == "__main__":
    unittest.main()
