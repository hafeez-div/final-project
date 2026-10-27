"""
DigitalShield Web Discovery & Reverse Image Search Package.

Provides automated reverse image search, public candidate webpage scraping,
and perceptual hash verification.
"""

from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.page_enricher import deduplicate_urls, enrich_page, normalize_url
from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider
from digitalshield.web_discovery.service import WebDiscoveryService
from digitalshield.web_discovery.vision_provider import (
    CredentialError,
    VisionAPIError,
    VisionWebDetectionProvider,
)

__all__ = [
    "BaseReverseImageProvider",
    "VisionWebDetectionProvider",
    "CredentialError",
    "VisionAPIError",
    "WebDiscoveryResult",
    "WebDiscoverySession",
    "WebDiscoveryService",
    "normalize_url",
    "deduplicate_urls",
    "enrich_page",
]
