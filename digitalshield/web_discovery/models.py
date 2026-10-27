"""
Data models for DigitalShield Web Discovery (Automatic Reverse Image Search).

FORENSIC INTEGRITY & ETHICAL RULES:
- All results are probabilistic indicators requiring investigator review.
- Neutral terminology: 'Potential match', 'Candidate source', 'Awaiting investigator review'.
- Never claim exact match or proof of manipulation from visual similarity alone.
- Provider-reported matches are distinguished from independently calculated similarity.
- Video frame search is explicitly noted as not yet implemented for image-only results.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class WebDiscoveryResult(BaseModel):
    """
    A single candidate source page or media URL discovered via reverse image search.
    """
    result_id: str = Field(description="Unique result ID (e.g. WDR-2026-000001)")
    session_id: str = Field(description="Parent web discovery session ID (WDS-YYYY-XXXXXX)")
    evidence_id: str = Field(description="Associated evidence ID")
    case_id: str = Field(description="Associated case ID")

    # Source page metadata (from Scrapling enrichment)
    source_url: str = Field(description="Source page URL")
    page_title: Optional[str] = Field(default=None, description="Page title extracted from public HTML")
    domain: Optional[str] = Field(default=None, description="Domain of the source URL")
    media_url: Optional[str] = Field(default=None, description="Direct image/media URL if discovered")
    canonical_url: Optional[str] = Field(default=None, description="Canonical page URL if declared")
    platform: Optional[str] = Field(default=None, description="Identifiable platform name (e.g. Instagram, Reddit)")

    # Provider-reported similarity type
    provider_match_type: str = Field(
        description="Match type as reported by provider (e.g. 'EXACT_MATCH', 'PARTIAL_MATCH', 'SIMILAR', 'PAGE_WITH_IMAGE')"
    )
    provider_similarity: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Score reported by provider, if available (0.0-1.0)."
    )
    provider_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)  # alias for backwards compatibility

    # Independent perceptual hash similarity (calculated by DigitalShield)
    ahash_distance: Optional[int] = Field(default=None, description="Hamming distance for aHash (0-64)")
    dhash_distance: Optional[int] = Field(default=None, description="Hamming distance for dHash (0-64)")
    phash_distance: Optional[int] = Field(default=None, description="Hamming distance for pHash (0-64)")
    calculated_similarity: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Perceptual similarity score calculated by DigitalShield (aHash+dHash+pHash average)"
    )
    independent_similarity_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    independent_matching_method: Optional[str] = Field(default=None)

    # Retrieval info
    discovery_timestamp: Optional[str] = Field(default=None, description="Timestamp when candidate was discovered")
    publication_timestamp: Optional[str] = Field(default=None, description="Public page date if discovered")
    retrieval_timestamp: str = Field(description="ISO 8601 UTC timestamp when this result was processed")
    scrape_status: str = Field(default="SUCCESS", description="Scraping status: SUCCESS, FAILED, TIMEOUT, BLOCKED")
    retrieval_status: str = Field(default="RETRIEVED")

    # Match classification
    verification_status: str = Field(
        default="Awaiting investigator review",
        description="Classification: Exact or near-exact perceptual match, High visual similarity, "
                    "Partial or cropped similarity, Low similarity, Unable to verify, Awaiting investigator review"
    )
    status: str = Field(default="Source discovered")

    notes: Optional[str] = Field(default=None, description="Retrieval notices or investigator notes")
    limitations: List[str] = Field(default_factory=list)

    @property
    def discovery_id(self) -> str:
        return self.session_id

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["discovery_id"] = self.session_id
        if d.get("provider_similarity") is not None and d.get("provider_score") is None:
            d["provider_score"] = d["provider_similarity"]
        if d.get("calculated_similarity") is not None and d.get("independent_similarity_score") is None:
            d["independent_similarity_score"] = d["calculated_similarity"]
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "WebDiscoveryResult":
        d = dict(data)
        if "session_id" not in d and "discovery_id" in d:
            d["session_id"] = d["discovery_id"]
        if "provider_similarity" not in d and "provider_score" in d:
            d["provider_similarity"] = d["provider_score"]
        if "calculated_similarity" not in d and "independent_similarity_score" in d:
            d["calculated_similarity"] = d["independent_similarity_score"]
        return cls(**d)


class WebDiscoverySession(BaseModel):
    """
    A complete automatic web discovery session for one evidence item.
    """
    session_id: str = Field(description="Unique session ID (e.g. WDS-2026-000001)")
    case_id: str = Field(description="Associated case ID")
    evidence_id: str = Field(description="Associated evidence ID")
    provider: str = Field(default="Google Cloud Vision Web Detection")
    started_at: str = Field(description="ISO 8601 UTC timestamp when search started")
    completed_at: Optional[str] = Field(default=None, description="ISO 8601 UTC timestamp when completed")

    status: str = Field(
        default="COMPLETED",
        description="Session status: COMPLETED, FAILED, NO_RESULTS, MISSING_CREDENTIALS, PARTIAL"
    )
    error_message: Optional[str] = Field(default=None, description="Error message if session failed")

    total_results: int = Field(default=0, description="Total candidate pages discovered")
    verified_matches: int = Field(default=0, description="Number of verified perceptual matches")
    unverified_results: int = Field(default=0, description="Unverified results (e.g. page without media)")
    failed_sources: int = Field(default=0, description="Sources that failed scraping or fetching")

    best_guess_labels: List[str] = Field(default_factory=list)
    is_video_evidence: bool = Field(default=False)
    video_search_note: Optional[str] = Field(default=None)
    limitations: List[str] = Field(default_factory=list)

    @property
    def discovery_id(self) -> str:
        return self.session_id

    @property
    def search_timestamp(self) -> str:
        return self.started_at

    @property
    def total_candidates(self) -> int:
        return self.total_results

    @property
    def results_count(self) -> int:
        return self.total_results

    def to_dict(self) -> dict:
        d = self.model_dump()
        d["discovery_id"] = self.session_id
        d["search_timestamp"] = self.started_at
        d["total_candidates"] = self.total_results
        d["results_count"] = self.total_results
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "WebDiscoverySession":
        d = dict(data)
        if "session_id" not in d and "discovery_id" in d:
            d["session_id"] = d["discovery_id"]
        if "started_at" not in d and "search_timestamp" in d:
            d["started_at"] = d["search_timestamp"]
        if "total_results" not in d and "total_candidates" in d:
            d["total_results"] = d["total_candidates"]
        return cls(**d)
