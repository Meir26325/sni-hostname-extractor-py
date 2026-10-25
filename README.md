# sni-hostname-extractor-py

Extract the Server Name Indication (SNI) hostname from the bytes of a TLS ClientHello record. Pure Python, standard library only.

```python
from sni_hostname_extractor_py import extract_sni, SNIExtractionError

# `record` is the raw bytes of one complete TLS record.
record = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00"
try:
    host = extract_sni(record)
except SNIExtractionError as exc:
    host = None  # malformed ClientHello
```

`extract_sni(data: bytes) -> str | None` returns the lowercased ASCII hostname, or `None` when the ClientHello is well-formed but carries no `server_name` extension. It raises `SNIExtractionError` if the bytes are not a recognizable ClientHello or if any length field is inconsistent with the buffer size.

## Why this exists

Network capture tools often need the SNI to route, log, or filter TLS traffic without terminating the connection. Doing that in Python usually means pulling in a large packet-parsing framework for the sake of one field. This library does exactly one walk over one ClientHello and returns one string — nothing else. The trade-off: you must hand it a complete, reassembled TLS record; it does not buffer or coalesce fragments.

## The awkward edge

The ClientHello is a length-prefixed onion of nested fields where every length is attacker-controllable. A host that sends an inconsistent length can crash a naive parser or, worse, make it read past the intended boundary. This library treats every length field as untrusted: if a length would walk off the end of its container, it raises `SNIExtractionError` rather than reading garbage. One consequence: a capture truncated mid-record is an error, not a partial result — reassemble first, then call.
