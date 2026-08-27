"""
Data models for DigitalShield perceptual fingerprinting and similarity comparison.

FORENSIC INTEGRITY RULES:
- Fingerprints are derived analysis artifacts, NEVER original evidence.
- Perceptual similarity is probabilistic and does NOT constitute forensic certainty
  regarding identity, common origin, authorship, or authenticity/falsity.
"""

from typing import Dict, Optional
from pydantic import BaseModel, Field


class AlgorithmFingerprint(BaseModel):
    """
    Individual algorithm perceptual fingerprint details.
    """
    algorithm: str = Field(description="Algorithm identifier (e.g. aHash, dHash, pHash)")
    hash_value: str = Field(description="Hexadecimal string representation of perceptual hash")
    bit_length: int = Field(default=64, description="Bit length of the perceptual hash representation")


class FingerprintResult(BaseModel):
    """
    Complete set of perceptual fingerprints extracted from an evidence image.
    Stored under .digitalshield_data/ as derived analysis.
    """
    evidence_id: str = Field(description="Associated Evidence ID (e.g. EVD-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    original_filename: Optional[str] = Field(default=None, description="Original filename of the evidence")
    generation_timestamp: str = Field(description="ISO 8601 UTC timestamp of fingerprint generation")
    
    ahash: str = Field(description="Average Hash (aHash) 64-bit hexadecimal digest")
    dhash: str = Field(description="Difference Hash (dHash) 64-bit hexadecimal digest")
    phash: str = Field(description="Perceptual Hash (pHash) 64-bit hexadecimal digest")
    
    algorithms: Dict[str, AlgorithmFingerprint] = Field(
        default_factory=dict,
        description="Per-algorithm detailed fingerprint records"
    )
    disclaimer: str = Field(
        default=(
            "Perceptual similarity is a probabilistic analysis and does NOT constitute "
            "forensic proof of identity, common origin, authorship, or authenticity/falsity."
        ),
        description="Forensic limitations and ethics disclaimer"
    )
    status: str = Field(default="COMPLETED", description="Status of fingerprint extraction")

    def to_dict(self) -> dict:
        """Convert FingerprintResult model to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "FingerprintResult":
        """Construct FingerprintResult from dictionary."""
        return cls(**data)


class ComparisonMetric(BaseModel):
    """
    Comparison metric for a single perceptual hashing algorithm.
    """
    algorithm: str = Field(description="Algorithm name (e.g. aHash, dHash, pHash)")
    hash_a: str = Field(description="Perceptual hash from Evidence A")
    hash_b: str = Field(description="Perceptual hash from Evidence B")
    hamming_distance: int = Field(description="Hamming distance (differing bits, 0 to 64)")
    max_distance: int = Field(default=64, description="Maximum possible Hamming distance")
    normalized_similarity: float = Field(
        description="Normalized similarity score between 0.0 (dissimilar) and 1.0 (identical hash)"
    )


class ComparisonResult(BaseModel):
    """
    Forensic comparison assessment between two preserved evidence items.
    """
    evidence_id_a: str = Field(description="Evidence ID for Item A")
    evidence_id_b: str = Field(description="Evidence ID for Item B")
    filename_a: Optional[str] = Field(default=None, description="Original filename for Item A")
    filename_b: Optional[str] = Field(default=None, description="Original filename for Item B")
    comparison_timestamp: str = Field(description="ISO 8601 UTC timestamp of comparison execution")
    metrics: Dict[str, ComparisonMetric] = Field(
        description="Per-algorithm comparison metrics for aHash, dHash, and pHash"
    )
    overall_similarity: float = Field(
        description="Overall normalized similarity score across algorithms (0.0 to 1.0)"
    )
    assessment: str = Field(
        description="Probabilistic assessment string describing perceptual similarity"
    )
    disclaimer: str = Field(
        default=(
            "Perceptual similarity scores are probabilistic derived indicators. A high similarity score "
            "does NOT prove that two files are identical, originated from the same source, or that an image "
            "is authentic or manipulated."
        ),
        description="Forensic and ethical limitation disclaimer"
    )

    def to_dict(self) -> dict:
        """Convert ComparisonResult model to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "ComparisonResult":
        """Construct ComparisonResult from dictionary."""
        return cls(**data)
