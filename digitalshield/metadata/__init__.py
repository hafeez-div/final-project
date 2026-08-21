"""
Metadata extraction package for parsing technical file headers, EXIF information, and structural anomalies.
"""

from digitalshield.metadata.models import MetadataResult
from digitalshield.metadata.extractor import MetadataExtractor

__all__ = ["MetadataResult", "MetadataExtractor"]
