"""
Data models for DigitalShield Public URL Provenance Analysis (Phase 7).

FORENSIC INTEGRITY & ETHICAL RULES:
- Provenance records are derived analysis artifacts, NEVER original evidence.
- Information from public sources must use neutral terminology: "Reported source", "Observed account",
  "Publicly observed source", "Investigative lead", "Evidence-supported association".
- Never infer who created, uploaded, or owns the content based on visual similarity or public observation.
- Never state that an account holder or individual is guilty or responsible.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class ProvenanceRecord(BaseModel):
    """
    Structured forensic record for public URL provenance observation and media similarity analysis.
    """
    provenance_id: str = Field(description="Unique Provenance ID (e.g. PRV-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    evidence_id: str = Field(description="Associated Evidence ID (e.g. EVD-2026-000001)")

    source_url: str = Field(description="Public HTTP/HTTPS URL observed")
    discovery_timestamp: str = Field(description="ISO 8601 UTC timestamp of observation")
    source_domain: str = Field(description="Domain extracted from the public URL")

    source_title: Optional[str] = Field(default=None, description="Publicly visible page title, if available")
    observed_account_name: Optional[str] = Field(default=None, description="Publicly visible account handle or username, if available")
    media_url: Optional[str] = Field(default=None, description="Public media URL extracted or observed, if available")

    similarity_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Perceptual similarity score between public media and evidence image (0.0 to 1.0)"
    )
    matching_method: Optional[str] = Field(
        default=None,
        description="Perceptual hashing method used for comparison (e.g. 'pHash + aHash + dHash')"
    )
    source_status: str = Field(default="ACCESSIBLE", description="Access status of the public URL")
    source_timestamp: Optional[str] = Field(
        default=None,
        description="Timestamp explicitly visible on the public source page, if available"
    )

    notes: Optional[str] = Field(default=None, description="Investigator notes or context")
    assessment: str = Field(description="Neutral, probabilistic assessment of provenance observation")
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit forensic limitations, calibration constraints, and operational caveats"
    )
    status: str = Field(default="COMPLETED", description="Execution status of provenance record")

    def to_dict(self) -> dict:
        """Convert ProvenanceRecord to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "ProvenanceRecord":
        """Construct ProvenanceRecord from dictionary."""
        return cls(**data)
