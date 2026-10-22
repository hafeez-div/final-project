"""
Data models for DigitalShield evidence management.
"""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """
    Evidence model representing forensic media/document metadata, SHA-256 digest, and vault path.
    """
    evidence_id: str = Field(description="Unique evidence identifier (e.g. EVD-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    original_filename: str = Field(description="Original filename at ingestion time")
    stored_filename: str = Field(description="Preserved filename within the evidence vault")
    stored_path: str = Field(description="Absolute path to preserved read-only file copy")
    file_size: int = Field(description="File size in bytes")
    mime_type: str = Field(description="Inferred MIME type (e.g. image/jpeg, text/plain)")
    source_url: Optional[str] = Field(default=None, description="Optional public source URL where evidence was observed")
    import_timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 import timestamp in UTC"
    )
    sha256: str = Field(description="Cryptographic SHA-256 hash digest")
    status: str = Field(default="PRESERVED", description="Preservation status (e.g. PRESERVED)")

    def to_dict(self) -> dict:
        """Convert evidence model to dictionary format."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "Evidence":
        """Construct Evidence instance from dictionary."""
        return cls(**data)
