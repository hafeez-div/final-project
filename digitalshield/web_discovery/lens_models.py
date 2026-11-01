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
from typing import List, Optional, Tuple
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
# Order matters: more specific entries should come before generic ones.
POPULAR_PLATFORMS = {
    "instagram.com": "Instagram",
    "cdninstagram.com": "Instagram",
    "facebook.com": "Facebook",
    "fbcdn.net": "Facebook",
    "fb.com": "Facebook",
    "fb.watch": "Facebook",
    "twitter.com": "X (Twitter)",
    "x.com": "X (Twitter)",
    "t.co": "X (Twitter)",
    "pbs.twimg.com": "X (Twitter)",
    "reddit.com": "Reddit",
    "redd.it": "Reddit",
    "i.redd.it": "Reddit",
    "preview.redd.it": "Reddit",
    "pinterest.com": "Pinterest",
    "pinimg.com": "Pinterest",
    "tiktok.com": "TikTok",
    "tiktokcdn.com": "TikTok",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "ytimg.com": "YouTube",
    "ggpht.com": "YouTube",
    "linkedin.com": "LinkedIn",
    "licdn.com": "LinkedIn",
    "tumblr.com": "Tumblr",
    "flickr.com": "Flickr",
    "staticflickr.com": "Flickr",
    "live.staticflickr.com": "Flickr",
    "wikipedia.org": "Wikipedia",
    "wikimedia.org": "Wikimedia",
    "upload.wikimedia.org": "Wikimedia",
    "commons.wikimedia.org": "Wikimedia",
    "fandom.com": "Fandom Wiki",
    "imgur.com": "Imgur",
    "i.imgur.com": "Imgur",
    "deviantart.com": "DeviantArt",
    "wixstatic.com": "Wix",
    "squarespace-cdn.com": "Squarespace",
    "wordpress.com": "WordPress",
    "blogspot.com": "Blogger",
    "blogger.com": "Blogger",
    "medium.com": "Medium",
    "substack.com": "Substack",
    "quora.com": "Quora",
    "gettyimages.com": "Getty Images",
    "gettyimages.co.uk": "Getty Images",
    "istockphoto.com": "iStockPhoto",
    "shutterstock.com": "Shutterstock",
    "alamy.com": "Alamy",
    "depositphotos.com": "DepositPhotos",
    "dreamstime.com": "Dreamstime",
    "adobe.com": "Adobe Stock",
    "imdb.com": "IMDb",
    "themoviedb.org": "TMDB",
    "amazon.com": "Amazon",
    "primevideo.com": "Prime Video",
    "netflix.com": "Netflix",
    "bbc.com": "BBC",
    "bbc.co.uk": "BBC",
    "cnn.com": "CNN",
    "nytimes.com": "New York Times",
    "theguardian.com": "The Guardian",
    "dailymail.co.uk": "Daily Mail",
    "apnews.com": "AP News",
    "reuters.com": "Reuters",
}

# Google-hosted CDN/thumbnail domains — these are NOT publishing websites
GOOGLE_THUMBNAIL_DOMAINS = {
    "encrypted-tbn0.gstatic.com",
    "encrypted-tbn1.gstatic.com",
    "encrypted-tbn2.gstatic.com",
    "encrypted-tbn3.gstatic.com",
    "lh1.googleusercontent.com",
    "lh2.googleusercontent.com",
    "lh3.googleusercontent.com",
    "lh4.googleusercontent.com",
    "lh5.googleusercontent.com",
    "lh6.googleusercontent.com",
    "gstatic.com",
    "ssl.gstatic.com",
    "t0.gstatic.com",
    "t1.gstatic.com",
    "t2.gstatic.com",
    "t3.gstatic.com",
    "googleusercontent.com",
}

# Source type classification by platform
SOURCE_TYPE_MAP = {
    "Instagram": "Social Media Post",
    "X (Twitter)": "Social Media Post",
    "Facebook": "Social Media Post",
    "TikTok": "Social Media Video",
    "Reddit": "Public Forum Post",
    "YouTube": "Video Platform",
    "Pinterest": "Image Board Post",
    "LinkedIn": "Professional Network Post",
    "Tumblr": "Blog Post",
    "Flickr": "Photo Hosting Page",
    "Wikipedia": "Encyclopedia Article",
    "Wikimedia": "Media Repository",
    "Fandom Wiki": "Fan Wiki Article",
    "Imgur": "Image Hosting Page",
    "DeviantArt": "Art Portfolio Page",
    "Medium": "Blog Article",
    "Substack": "Newsletter Article",
    "Quora": "Q&A Forum Post",
    "Getty Images": "Stock Image Listing",
    "iStockPhoto": "Stock Image Listing",
    "Shutterstock": "Stock Image Listing",
    "Alamy": "Stock Image Listing",
    "DepositPhotos": "Stock Image Listing",
    "Dreamstime": "Stock Image Listing",
    "Adobe Stock": "Stock Image Listing",
    "IMDb": "Movie/TV Database Page",
    "TMDB": "Movie/TV Database Page",
    "Amazon": "E-Commerce Listing",
    "Prime Video": "Streaming Platform",
    "Netflix": "Streaming Platform",
    "BBC": "News Article",
    "CNN": "News Article",
    "New York Times": "News Article",
    "The Guardian": "News Article",
    "Daily Mail": "News Article",
    "AP News": "News Article",
    "Reuters": "News Article",
}


def is_google_thumbnail_url(url: str) -> bool:
    """
    Return True if the URL points to a Google-hosted thumbnail or CDN image.
    These are NOT the original publishing webpage and should be labeled as thumbnails only.
    """
    try:
        netloc = urlparse(url.strip()).netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        if netloc in GOOGLE_THUMBNAIL_DOMAINS:
            return True
        for gdom in GOOGLE_THUMBNAIL_DOMAINS:
            if netloc.endswith("." + gdom):
                return True
        return False
    except Exception:
        return False


def detect_platform_name(url: str) -> str:
    """
    Extract recognized platform name from a URL domain.
    Returns the platform name (e.g. 'Reddit', 'Instagram') or the bare domain.
    Google thumbnail URLs return 'Google (Thumbnail Cache)'.
    """
    try:
        parsed = urlparse(url.strip())
        netloc = parsed.netloc.lower()
        if netloc.startswith("www."):
            netloc = netloc[4:]
        if is_google_thumbnail_url(url):
            return "Google (Thumbnail Cache)"
        for domain, name in POPULAR_PLATFORMS.items():
            if netloc == domain or netloc.endswith("." + domain):
                return name
        return netloc or "Web Source"
    except Exception:
        return "Web Source"


def detect_source_type(platform_name: str, url: str = "") -> str:
    """
    Return a human-readable source type label for the given platform.
    """
    if platform_name == "Google (Thumbnail Cache)":
        return "Google Thumbnail Cache (not original publisher)"
    if platform_name in SOURCE_TYPE_MAP:
        return SOURCE_TYPE_MAP[platform_name]
    # Guess from URL patterns
    url_lower = url.lower()
    if "/wiki/" in url_lower or "wikipedia" in url_lower:
        return "Encyclopedia Article"
    if "forum" in url_lower or "thread" in url_lower or "discuss" in url_lower:
        return "Public Forum Post"
    if "blog" in url_lower or "post" in url_lower:
        return "Blog or Article Page"
    if "video" in url_lower or "watch" in url_lower:
        return "Video Platform Page"
    if "shop" in url_lower or "store" in url_lower or "product" in url_lower:
        return "E-Commerce Page"
    if "news" in url_lower or "article" in url_lower:
        return "News Article"
    return "Public Website"


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
