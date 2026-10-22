"""
Data models for DigitalShield case management.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class Case(BaseModel):
    """
    Forensic Case model representing investigation metadata and container paths.
    """
    case_id: str = Field(description="Unique case identifier (e.g. DS-2026-000001)")
    name: str = Field(description="Human-readable case name")
    investigator: str = Field(default="Unassigned", description="Name or email of investigator")
    description: str = Field(default="", description="Case description or notes")
    source_url: Optional[str] = Field(default=None, description="Reported public source URL supplied by investigator")
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 creation timestamp in UTC"
    )
    status: str = Field(default="OPEN", description="Case status (OPEN, CLOSED, ARCHIVED)")
    vault_path: str = Field(description="Local filesystem directory path for evidence vault")
    evidence_count: int = Field(default=0, description="Total number of evidence items ingested")

    def to_dict(self) -> dict:
        """Convert case model to dictionary format."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "Case":
        """Construct Case instance from dictionary."""
        return cls(**data)
