"""
DigitalShield Web Discovery & Reverse Image Search Package.

Provides automated reverse image search, public candidate webpage scraping,
and perceptual hash verification.
"""

from digitalshield.web_discovery.google_lens_provider import (
    GoogleLensProvider,
    ReverseSearchProviderError,
)
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.page_enricher import deduplicate_urls, enrich_page, normalize_url
from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider
from digitalshield.web_discovery.service import (
    CredentialError,
    ProviderError,
    WebDiscoveryService,
)

__all__ = [
    "BaseReverseImageProvider",
    "GoogleLensProvider",
    "ReverseSearchProviderError",
    "CredentialError",
    "ProviderError",
    "WebDiscoveryResult",
    "WebDiscoverySession",
    "WebDiscoveryService",
    "normalize_url",
    "deduplicate_urls",
    "enrich_page",
]
