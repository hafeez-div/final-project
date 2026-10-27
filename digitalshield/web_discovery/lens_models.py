"""
Data models for DigitalShield Google Lens Reverse Image Search Workflow
(Investigator-Assisted Public Reverse Image Search).

FORENSIC INTEGRITY & ETHICAL RULES:
- Results represent investigator-recorded findings from Google Lens.
- Search coverage is limited to publicly accessible and indexed content.
- The absence of a result does not establish that an image has never been published online.
- All entries are recorded neutrally: 'Visually similar image', 'Exact image match', etc.
- No result constitutes proof of unauthorized distribution, identity, or manipulation.
- Evidence files remain read-only and immutable.
"""

from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator


# Documented supported categories for Google Lens matches
GOOGLE_LENS_CATEGORIES = [
    "Visually similar image",
    "Exact image match",
    "Cropped or edited image",
    "Social-media result",
    "Other public webpage",
]

# Recognizable social media / platform domains for automatic or manual tagging
POPULAR_PLATFORMS = {
    "instagram.com": "Instagram",
    "facebook.com": "Facebook",
    "fb.com": "Facebook",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "reddit.com": "Reddit",
    "pinterest.com": "Pinterest",
    "tiktok.com": "TikTok",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "linkedin.com": "LinkedIn",
    "tumblr.com": "Tumblr",
    "flickr.com": "Flickr",
    "wikipedia.org": "Wikipedia",
    "wikimedia.org": "Wikimedia",
}


def detect_platform_name(url: str) -> str:
    """Extract domain or recognized platform name from a URL."""
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        for domain, name in POPULAR_PLATFORMS.items():
            if netloc == domain or netloc.endswith("." + domain):
                return name
        return netloc or "Web Source"
    except Exception:
        return "Web Source"


def validate_http_url(url: str, field_name: str = "URL") -> str:
    """Validate that a URL uses HTTP or HTTPS scheme and has a valid host."""
    trimmed = (url or "").strip()
    if not trimmed:
        raise ValueError(f"{field_name} cannot be empty.")
    try:
        parsed = urlparse(trimmed)
    except Exception as e:
        raise ValueError(f"Invalid {field_name} format: {e}")

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError(
            f"{field_name} must use http:// or https:// scheme (received '{scheme}://'). "
            "file://, ftp://, and local schemes are prohibited."
        )
    if not parsed.netloc:
        raise ValueError(f"{field_name} must include a valid domain or host name.")
    return trimmed


class GoogleLensResult(BaseModel):
    """
    A single investigator-recorded match result from a Google Lens search session.
    """
    result_id: str = Field(description="Unique result ID (e.g. GLR-2026-000001)")
    session_id: str = Field(description="Parent search session ID (GLS-YYYY-XXXXXX)")
    evidence_id: str = Field(description="Associated evidence ID (EVD-YYYY-XXXXXX)")
    case_id: str = Field(description="Associated case ID (DS-YYYY-XXXXXX)")

    # Required URL & platform information
    source_url: str = Field(description="Matching webpage URL (HTTP/HTTPS only)")
    platform_name: str = Field(
        default="Web Source",
        description="Website or platform name (e.g. Instagram, Reddit, Wikipedia)"
    )
    page_title: Optional[str] = Field(
        default=None,
        description="Page title or description observed by investigator"
    )
    media_url: Optional[str] = Field(
        default=None,
        description="Direct matched image/media URL, if observed"
    )

    # Classification
    search_category: str = Field(
        default="Visually similar image",
        description="Search match category (from GOOGLE_LENS_CATEGORIES)"
    )

    search_provider: str = Field(
        default="Google Lens (Manual)",
        description="Provider designation"
    )
    recorded_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when this match was recorded"
    )
    investigator_notes: Optional[str] = Field(
        default=None,
        description="Investigator observations or verification notes"
    )

    limitations: List[str] = Field(
        default_factory=lambda: [
            "This finding represents an investigator-recorded result from Google Lens.",
            "Search coverage is limited to publicly accessible and indexed content.",
            "The absence of a result does not establish that an image has never been published online.",
            "Visual similarity does not prove unauthorized distribution, original authorship, or tampering.",
        ]
    )

    @field_validator("source_url")
    @classmethod
    def validate_source(cls, v: str) -> str:
        return validate_http_url(v, field_name="Matching webpage URL")

    @field_validator("media_url")
    @classmethod
    def validate_media(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return validate_http_url(v, field_name="Matching image URL")
        return None

    def to_dict(self) -> dict:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "GoogleLensResult":
        return cls(**data)


class GoogleLensSession(BaseModel):
    """
    An investigator-assisted Google Lens reverse image search session for one evidence item.
    """
    session_id: str = Field(description="Unique session ID (e.g. GLS-2026-000001)")
    evidence_id: str = Field(description="Associated evidence ID")
    case_id: str = Field(description="Associated case ID")
    provider: str = Field(default="Google Lens (Manual)")
    search_url: str = Field(
        default="https://lens.google.com/",
        description="Official Google Lens search portal URL"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO 8601 UTC timestamp when the session was initiated"
    )
    status: str = Field(
        default="ACTIVE",
        description="Session status: ACTIVE, COMPLETED, NO_RESULTS"
    )
    results_count: int = Field(default=0, description="Total matching results recorded in this session")
    investigator_notes: Optional[str] = Field(default=None, description="General session notes")

    limitations: List[str] = Field(
        default_factory=lambda: [
            "These findings represent investigator-recorded results from Google Lens.",
            "Search coverage is limited to publicly accessible and indexed content.",
            "The absence of a result does not establish that an image has never been published online.",
            "Visual similarity does not prove unauthorized distribution, original authorship, or identity.",
        ]
    )

    def to_dict(self) -> dict:
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "GoogleLensSession":
        return cls(**data)
