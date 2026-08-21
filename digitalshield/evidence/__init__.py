"""
Evidence management package handling evidence ingestion, SHA-256 baseline hashing, and read-only vault preservation.
"""

from digitalshield.evidence.models import Evidence
from digitalshield.evidence.manager import EvidenceManager, SUPPORTED_EXTENSIONS

__all__ = ["Evidence", "EvidenceManager", "SUPPORTED_EXTENSIONS"]
