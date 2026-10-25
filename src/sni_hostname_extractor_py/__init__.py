"""sni-hostname-extractor-py

Parse a TLS ClientHello record and return the Server Name Indication
(SNI) hostname. Pure Python, no third-party dependencies.
"""

from .core import extract_sni, SNIExtractionError

__all__ = ["extract_sni", "SNIExtractionError"]
