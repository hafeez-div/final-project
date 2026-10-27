"""
Scrapling-based page enricher for DigitalShield Web Discovery.

Retrieves and parses publicly accessible candidate webpages returned by
the Vision API, extracting page title, domain, direct media URL, and
retrieval metadata.

SECURITY RULES:
- Reuses DigitalShield's existing SafePublicClient for SSRF protection:
  redirect validation, private-address blocking, timeouts, response-size limits.
- Only accesses public HTTP/HTTPS resources.
- Does NOT bypass login, CAPTCHAs, or access controls.
- Stores no cookies, credentials, or session state.
- The Google API key is NEVER passed to Scrapling or any third-party site.

SCRAPING RULES:
- Extracts only publicly visible metadata: title, domain, image/media URLs.
- Never stores full page content; only extracted metadata is persisted.
- Deduplicates normalized URLs before enrichment to avoid redundant requests.
"""

import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional

from digitalshield.provenance.client import SafePublicClient

# Reuse the existing SSRF-safe client
_DEFAULT_CLIENT = None


def _get_client() -> SafePublicClient:
    global _DEFAULT_CLIENT
    if _DEFAULT_CLIENT is None:
        _DEFAULT_CLIENT = SafePublicClient(timeout=10, max_bytes=5 * 1024 * 1024)
    return _DEFAULT_CLIENT


def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication: strip trailing slash, lowercase scheme, host, and path.
    """
    try:
        p = urllib.parse.urlparse(url.strip())
        path = p.path.lower().rstrip("/") or "/"
        norm = urllib.parse.urlunparse((
            p.scheme.lower(),
            p.netloc.lower(),
            path,
            p.params,
            p.query,
            ""  # drop fragment
        ))
        return norm
    except Exception:
        return url.strip()


def deduplicate_urls(urls: List[str]) -> List[str]:
    """
    Return a deduplicated list preserving first occurrence order.
    """
    seen = set()
    result = []
    for url in urls:
        norm = normalize_url(url)
        if norm not in seen:
            seen.add(norm)
            result.append(url)
    return result


def _extract_image_urls_from_html(html_content: bytes) -> List[str]:
    """
    Extract <img src> URLs from HTML using lxml via Scrapling's Selector.
    Returns an empty list if Scrapling parsing fails.
    """
    try:
        from scrapling import Selector
        text = html_content.decode("utf-8", errors="ignore")
        sel = Selector(text)
        # Collect <img src>, <meta property="og:image">, <link rel="image_src">
        imgs = []
        for img_src in sel.css("img[src]::attr(src)").getall():
            imgs.append(img_src.strip())
        for og in sel.css("meta[property='og:image']::attr(content)").getall():
            imgs.append(og.strip())
        for li in sel.css("link[rel='image_src']::attr(href)").getall():
            imgs.append(li.strip())
        return [u for u in imgs if u and u.startswith(("http://", "https://"))]
    except Exception:
        return []


def enrich_page(
    page_url: str,
    client: Optional[SafePublicClient] = None,
    provided_title: Optional[str] = None,
    provided_media_urls: Optional[List[str]] = None,
) -> Dict:
    """
    Safely fetch a public candidate page and extract metadata.

    Returns a dict with keys:
        source_url, page_title, domain, media_url,
        retrieval_timestamp, retrieval_status, notes
    """
    if client is None:
        client = _get_client()

    retrieval_timestamp = datetime.now(timezone.utc).isoformat()
    domain = None
    try:
        parsed = urllib.parse.urlparse(page_url)
        domain = parsed.netloc
    except Exception:
        pass

    result = {
        "source_url": page_url,
        "page_title": provided_title,
        "domain": domain,
        "media_url": None,
        "retrieval_timestamp": retrieval_timestamp,
        "retrieval_status": "PENDING",
        "notes": None,
    }

    try:
        # SSRF check first (validate_url raises ValueError on private addresses)
        validated_url = client.validate_url(page_url)
    except ValueError as ve:
        result["retrieval_status"] = "PRIVATE_ADDRESS_BLOCKED"
        result["notes"] = f"URL blocked by SSRF protection: {ve}"
        return result

    try:
        status_code, headers, content = client.fetch_public_url(validated_url)
    except ValueError as ve:
        msg = str(ve)
        if "Oversized" in msg:
            result["retrieval_status"] = "OVERSIZED"
        elif "Too many redirects" in msg:
            result["retrieval_status"] = "REDIRECT_LIMIT"
        elif "Failed to fetch" in msg:
            result["retrieval_status"] = "FETCH_FAILED"
        else:
            result["retrieval_status"] = "FETCH_FAILED"
        result["notes"] = msg[:300]
        # Preserve provider-reported URL even if fetch failed
        return result

    content_type = headers.get("content-type", "")

    if status_code >= 400:
        result["retrieval_status"] = f"HTTP_{status_code}"
        result["notes"] = f"HTTP {status_code} received from public resource."
        return result

    # Extract page title via Scrapling if HTML
    if not result["page_title"]:
        if "text/html" in content_type or content.strip().startswith(b"<"):
            try:
                from scrapling import Selector
                html_text = content.decode("utf-8", errors="ignore")
                sel = Selector(html_text)
                titles = sel.css("title::text").getall()
                if titles:
                    result["page_title"] = " ".join(titles).strip()[:200]
            except Exception:
                # Fallback to existing SafePublicClient method
                meta = client.extract_public_metadata(content, content_type)
                result["page_title"] = meta.get("source_title")

    # Determine media URL
    # 1. Use provider-supplied media URLs if already known
    if provided_media_urls:
        # Validate each through SSRF filter
        for murl in provided_media_urls:
            try:
                validated_murl = client.validate_url(murl)
                result["media_url"] = validated_murl
                break
            except ValueError:
                continue

    # 2. If the page itself is an image, use it directly
    if not result["media_url"] and content_type.startswith("image/"):
        result["media_url"] = validated_url

    # 3. Scrape <img> tags from HTML for first public image
    if not result["media_url"] and ("text/html" in content_type or content.strip().startswith(b"<")):
        img_urls = _extract_image_urls_from_html(content)
        for img_url in img_urls:
            try:
                client.validate_url(img_url)
                # Make absolute if relative
                abs_img = urllib.parse.urljoin(page_url, img_url)
                client.validate_url(abs_img)
                result["media_url"] = abs_img
                break
            except ValueError:
                continue

    result["retrieval_status"] = "RETRIEVED"
    return result
