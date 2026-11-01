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


def _extract_page_metadata_from_html(html_content: bytes, base_url: str = "") -> Dict:
    """
    Extract rich metadata from HTML using Scrapling's Selector.
    Extracts: page title, Open Graph title/image/url, canonical URL,
    publication timestamp, author, and the first usable image URL.

    Returns a dict with all extracted fields (may be None if not found).
    """
    result = {
        "page_title": None,
        "og_title": None,
        "og_image": None,
        "og_url": None,
        "canonical_url": None,
        "publication_timestamp": None,
        "author": None,
        "image_urls": [],
    }
    try:
        from scrapling import Selector
        text = html_content.decode("utf-8", errors="ignore")
        sel = Selector(text)

        # Page title
        titles = sel.css("title::text").getall()
        if titles:
            result["page_title"] = " ".join(titles).strip()[:200]

        # Open Graph metadata
        for prop in sel.css("meta[property]"):
            p = (prop.attrib.get("property") or "").lower()
            c = (prop.attrib.get("content") or "").strip()
            if not c:
                continue
            if p == "og:title":
                result["og_title"] = c[:200]
            elif p == "og:image":
                result["og_image"] = c
            elif p == "og:url":
                result["og_url"] = c
            elif p in ("article:published_time", "og:updated_time", "article:modified_time"):
                if not result["publication_timestamp"]:
                    result["publication_timestamp"] = c

        # Twitter Card metadata (fallback for og missing)
        for meta in sel.css("meta[name]"):
            n = (meta.attrib.get("name") or "").lower()
            c = (meta.attrib.get("content") or "").strip()
            if not c:
                continue
            if n == "twitter:title" and not result["og_title"]:
                result["og_title"] = c[:200]
            elif n == "twitter:image" and not result["og_image"]:
                result["og_image"] = c
            elif n in ("author", "article:author", "dc.creator") and not result["author"]:
                result["author"] = c[:100]

        # Canonical URL
        for link in sel.css("link[rel='canonical']"):
            href = (link.attrib.get("href") or "").strip()
            if href:
                result["canonical_url"] = href
                break

        # Publication timestamp from <time> elements
        if not result["publication_timestamp"]:
            pub_times = sel.css("time[datetime]::attr(datetime)").getall()
            if pub_times:
                result["publication_timestamp"] = pub_times[0].strip()

        # Collect image URLs from <img src>, og:image (already done), link[rel=image_src]
        imgs = []
        for img_src in sel.css("img[src]::attr(src)").getall():
            imgs.append(img_src.strip())
        for li in sel.css("link[rel='image_src']::attr(href)").getall():
            imgs.append(li.strip())
        # If og:image was found, put it first
        if result["og_image"]:
            imgs = [result["og_image"]] + imgs
        # Resolve relative URLs
        abs_imgs = []
        for img in imgs:
            if img.startswith(("http://", "https://")):
                abs_imgs.append(img)
            elif base_url and img.startswith("/"):
                abs_imgs.append(urllib.parse.urljoin(base_url, img))
        result["image_urls"] = abs_imgs

    except Exception:
        pass
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
        og_title, og_image, og_url, canonical_url,
        publication_timestamp, author,
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
        "og_title": None,
        "og_image": None,
        "og_url": None,
        "canonical_url": None,
        "author": None,
        "publication_timestamp": None,
        "http_status": None,
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
        result["http_status"] = status_code
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

    # Extract rich metadata if HTML
    if "text/html" in content_type or content.strip().startswith(b"<"):
        meta = _extract_page_metadata_from_html(content, base_url=validated_url)

        # Page title: prefer og:title for social platforms, then <title>
        if not result["page_title"]:
            result["page_title"] = meta.get("og_title") or meta.get("page_title")

        result["og_title"] = meta.get("og_title")
        result["og_image"] = meta.get("og_image")
        result["og_url"] = meta.get("og_url")
        result["canonical_url"] = result["canonical_url"] or meta.get("canonical_url")
        result["author"] = meta.get("author")
        result["publication_timestamp"] = result["publication_timestamp"] or meta.get("publication_timestamp")
        scraped_images = meta.get("image_urls", [])
    else:
        scraped_images = []

    # Determine media URL for perceptual hash comparison
    # 1. Use provider-supplied media URLs if already known
    if provided_media_urls:
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

    # 3. Use og:image if available (highest quality image reference from the page)
    if not result["media_url"] and result["og_image"]:
        try:
            validated_og = client.validate_url(result["og_image"])
            result["media_url"] = validated_og
        except ValueError:
            pass

    # 4. Scrape <img> tags from HTML
    if not result["media_url"] and scraped_images:
        for img_url in scraped_images:
            if img_url == result["og_image"]:
                continue  # already tried
            try:
                abs_img = urllib.parse.urljoin(page_url, img_url)
                client.validate_url(abs_img)
                result["media_url"] = abs_img
                break
            except ValueError:
                continue

    result["retrieval_status"] = "RETRIEVED"
    return result
