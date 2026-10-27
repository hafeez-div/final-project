"""
Data models for DigitalShield Forensic Report Generation (Phase 8).

FORENSIC INTEGRITY & ETHICAL RULES:
- Reports are compiled forensic summaries derived from preserved evidence and analysis artifacts.
- NEVER fabricates or guesses missing fields; unavailable data is explicitly noted.
- AI-assisted findings (ELA, Deepfake) are strictly labeled as probabilistic indicators.
- Neutral non-accusatory language is enforced throughout.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    """Metadata regarding the generated forensic report."""
    report_id: str = Field(description="Unique Report ID (e.g. RPT-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    case_name: str = Field(description="Human-readable case name")
    investigator: str = Field(default="Unassigned", description="Name or email of lead investigator")
    report_timestamp: str = Field(description="UTC ISO 8601 generation timestamp of report")
    report_version: str = Field(default="1.0", description="Forensic report format specification version")
    software_version: str = Field(default="0.1.0", description="DigitalShield software version")
    tool_name: str = Field(default="DigitalShield", description="Digital forensics suite name")


class CaseInfo(BaseModel):
    """Case lifecycle information for the forensic report."""
    case_id: str = Field(description="Unique case identifier")
    name: str = Field(description="Case title or description")
    investigator: str = Field(default="Unassigned", description="Assigned investigator")
    description: str = Field(default="", description="Case description or scope notes")
    source_url: Optional[str] = Field(default=None, description="Reported public source URL supplied by investigator")
    created_at: str = Field(description="UTC ISO 8601 case initialization timestamp")
    status: str = Field(default="OPEN", description="Case status (OPEN, CLOSED, ARCHIVED)")
    vault_path: str = Field(description="Local vault directory path")
    evidence_count: int = Field(default=0, description="Total evidence items ingested")


class EvidenceItemReport(BaseModel):
    """Forensic evidence item metadata for evidence inventory."""
    evidence_id: str = Field(description="Unique Evidence ID (e.g. EVD-2026-000001)")
    case_id: str = Field(description="Associated Case ID")
    original_filename: str = Field(description="Original filename at ingestion time")
    stored_filename: str = Field(description="Preserved filename within evidence vault")
    stored_path: str = Field(description="Preserved read-only vault path")
    file_size: int = Field(description="File size in bytes")
    mime_type: str = Field(description="MIME type")
    source_url: Optional[str] = Field(default=None, description="Reported public source URL supplied by investigator")
    import_timestamp: str = Field(description="UTC ISO 8601 ingestion timestamp")
    sha256: str = Field(description="Cryptographic SHA-256 hash digest")
    status: str = Field(default="PRESERVED", description="Preservation status")


class ReportData(BaseModel):
    """
    Consolidated, structured forensic data container used by all format renderers
    (Markdown, HTML, PDF) to ensure 100% data parity and zero divergent logic.
    """
    metadata: ReportMetadata
    case_info: CaseInfo
    evidence_items: List[EvidenceItemReport] = Field(default_factory=list)
    
    # Derived forensic analysis results (keyed by evidence_id)
    metadata_findings: Dict[str, Optional[Dict[str, Any]]] = Field(default_factory=dict)
    fingerprint_findings: Dict[str, Optional[Dict[str, Any]]] = Field(default_factory=dict)
    ela_findings: Dict[str, Optional[Dict[str, Any]]] = Field(default_factory=dict)
    deepfake_findings: Dict[str, Optional[Dict[str, Any]]] = Field(default_factory=dict)
    
    # Public provenance & propagation
    provenance_records: List[Dict[str, Any]] = Field(default_factory=list)
    timelines: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    
    # Audit trail & chain of custody
    audit_events: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Summaries and limitations
    overall_findings: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    investigator_notes: Optional[str] = Field(default=None)

    # Reported public source URL (supplied by investigator)
    reported_source_url: Optional[str] = Field(default=None, description="Exact public source URL entered by investigator")
    reported_source_url_recorded_at: Optional[str] = Field(default=None, description="UTC timestamp when public source URL was recorded")
    reported_source_url_status: Optional[str] = Field(default=None, description="Verification status of reported source URL")
    reported_source_url_evidence_id: Optional[str] = Field(default=None, description="Associated evidence ID")

    # Public Image / Video Source Discovery (Google Cloud Vision Web Detection)
    web_discovery_sessions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Web discovery session records (one per evidence item searched)"
    )
    web_discovery_results: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Individual discovered source results from web discovery sessions"
    )

    def to_dict(self) -> dict:
        """Convert ReportData to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "ReportData":
        """Construct ReportData from dictionary."""
        return cls(**data)


class ReportRecord(BaseModel):
    """
    Lightweight index record persisted in reports.json and returned to CLI callers.
    """
    report_id: str = Field(description="Unique Report ID (e.g. RPT-2026-000001)")
    case_id: str = Field(description="Associated Case ID")
    generation_timestamp: str = Field(description="UTC ISO 8601 generation timestamp")
    formats_generated: List[str] = Field(description="List of formats generated (markdown, html, pdf)")
    files: Dict[str, str] = Field(description="Mapping of format name to generated file path")
    status: str = Field(default="GENERATED", description="Report status")

    def to_dict(self) -> dict:
        """Convert ReportRecord to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "ReportRecord":
        """Construct ReportRecord from dictionary."""
        return cls(**data)
