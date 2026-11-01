"""
Google Lens Reverse Image Discovery Provider for DigitalShield.

FORENSIC INTEGRITY & TECHNICAL TRANSPARENCY:
- Google Lens does NOT offer an official public standalone developer API.
- Automated programmatic reverse image search is supported through compliant gateway
  services (such as SerpApi Google Lens engine via SERPAPI_API_KEY or GOOGLE_LENS_API_KEY).
- When a search gateway is configured, DigitalShield automatically submits the preserved
  vault image to the Google Lens reverse search engine and extracts candidate sources.
- When no gateway is configured or when running fully offline, this provider transparently
  reports that no matching public sources were discovered. It NEVER fabricates matches,
  never invents similarity scores, and never uses unauthorized CAPTCHA bypasses.
- All operations read strictly from the immutable, read-only evidence vault.
"""

import io
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from PIL import Image

from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider

REQUEST_TIMEOUT = 30  # seconds
MAX_IMAGE_BYTES = 20 * 1024 * 1024   # 20 MB absolute safety limit
MAX_GATEWAY_UPLOAD_BYTES = 500 * 1024  # 500 KB SerpApi upload limit
OPTIMIZED_TARGET_BYTES = 485 * 1024    # Target safely under 500 KB


class ReverseSearchProviderError(Exception):
    """Raised when the reverse image search provider encounters an error."""


class GoogleLensProvider(BaseReverseImageProvider):
    """
    Automated reverse image discovery provider using Google Lens.
    Operates on read-only evidence vault copies.
    """

    PROVIDER_NAME: str = "Google Lens"

    def __init__(self, api_key: Optional[str] = None):
        self._explicit_api_key = api_key

    def _get_gateway_api_key(self) -> Optional[str]:
        """
        Retrieve gateway API key from explicit setting or environment variables.
        Never hardcodes credentials.
        """
        if self._explicit_api_key:
            return self._explicit_api_key

        # Check standard environment variables for Google Lens gateway
        for var in ("SERPAPI_API_KEY", "SEARCHAPI_API_KEY", "GOOGLE_LENS_API_KEY", "LENS_API_KEY"):
            val = os.environ.get(var, "").strip()
            if val:
                return val
        return None

    @classmethod
    def _prepare_image_bytes(cls, image_path: Path) -> Tuple[bytes, str, str]:
        """
        Load image from read-only evidence vault and optimize for gateway upload.

        STRICT FORENSIC & INTEGRITY RULES:
        - NEVER modifies original evidence vault files.
        - Generates in-memory optimized payload under 500 KB when evidence exceeds limit.
        - Cleaned up in memory with zero leaked disk temporary files.

        Returns:
            Tuple of (payload_bytes, content_type, upload_filename)
        """
        with open(image_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) > MAX_IMAGE_BYTES:
            raise ValueError(
                f"Image ({len(raw_bytes) // (1024 * 1024)} MB) exceeds the absolute limit "
                f"of {MAX_IMAGE_BYTES // (1024 * 1024)} MB."
            )

        filename = image_path.name
        content_type = "image/jpeg"
        if filename.lower().endswith(".png"):
            content_type = "image/png"
        elif filename.lower().endswith(".webp"):
            content_type = "image/webp"

        # If already below gateway limit, return original bytes directly
        if len(raw_bytes) <= MAX_GATEWAY_UPLOAD_BYTES:
            return raw_bytes, content_type, filename

        # Evidence is > 500 KB: generate in-memory optimized JPEG
        with Image.open(io.BytesIO(raw_bytes)) as img:
            # Handle alpha transparency if converting to JPEG
            if img.mode in ("RGBA", "LA", "P"):
                rgb = Image.new("RGB", img.size, (255, 255, 255))
                if img.mode == "P":
                    img = img.convert("RGBA")
                mask = img.split()[3] if len(img.split()) == 4 else None
                rgb.paste(img, mask=mask)
            else:
                rgb = img.convert("RGB")

            # Progressive compression quality adjustment
            buf = io.BytesIO()
            for q in (85, 75, 65, 50):
                buf.seek(0)
                buf.truncate()
                rgb.save(buf, format="JPEG", quality=q, optimize=True)
                if buf.tell() <= OPTIMIZED_TARGET_BYTES:
                    break

            # If still > target, downscale dimensions
            if buf.tell() > OPTIMIZED_TARGET_BYTES:
                for max_dim in (1600, 1200, 1000, 800):
                    rgb.thumbnail((max_dim, max_dim), Image.LANCZOS)
                    buf.seek(0)
                    buf.truncate()
                    rgb.save(buf, format="JPEG", quality=75, optimize=True)
                    if buf.tell() <= OPTIMIZED_TARGET_BYTES:
                        break

            optimized_bytes = buf.getvalue()

        return optimized_bytes, "image/jpeg", f"{image_path.stem}.jpg"

    def search_web(self, image_path: Path) -> Dict[str, Any]:
        """
        Execute automated reverse image discovery on an evidence image file.

        Returns standardized dict:
            - full_matching_image_urls: List[str]
            - partial_matching_image_urls: List[str]
            - visually_similar_image_urls: List[str]
            - pages_with_matching_images: List[Dict] with 'url', 'page_title', 'score', 'full_images', 'partial_images'
            - web_entities: List[Dict]
            - best_guess_labels: List[str]
        """
        if not image_path.exists():
            raise FileNotFoundError(f"Evidence file not found: {image_path}")

        # If a custom mock or local gateway endpoint is provided via environment
        gateway_endpoint = os.environ.get("GOOGLE_LENS_ENDPOINT", "").strip()
        if gateway_endpoint:
            return self._query_custom_endpoint(image_path, gateway_endpoint)

        gateway_key = self._get_gateway_api_key()

        # When no external programmatic gateway is configured, raise an explicit error
        # rather than deceiving investigators with a fake empty NO_RESULTS session.
        if not gateway_key:
            raise ReverseSearchProviderError(
                "Reverse image search gateway is not configured. Google Lens does not provide "
                "an official unauthenticated public API. Configure SERPAPI_API_KEY, "
                "GOOGLE_LENS_API_KEY, or SEARCHAPI_API_KEY in your environment or .env file "
                "to enable automated online discovery."
            )

        # Check if SearchApi gateway is configured
        searchapi_key = os.environ.get("SEARCHAPI_API_KEY", "").strip()
        if searchapi_key and (gateway_key == searchapi_key or "searchapi" in gateway_key.lower()):
            return self._query_searchapi_gateway(image_path, searchapi_key)

        return self._query_lens_gateway(image_path, gateway_key)

    def _query_searchapi_gateway(self, image_path: Path, api_key: str) -> Dict[str, Any]:
        """
        Query SearchApi.io Google Lens engine via standard HTTPS multipart upload.
        """
        image_bytes, content_type, filename = self._prepare_image_bytes(image_path)
        boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
        body = io.BytesIO()

        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode("utf-8")
        )
        body.write(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.write(image_bytes)
        body.write(b"\r\n")

        for key, val in [("engine", "google_lens"), ("api_key", api_key)]:
            body.write(f"--{boundary}\r\n".encode("utf-8"))
            body.write(f'Content-Disposition: form-data; name="{key}"\r\n\r\n'.encode("utf-8"))
            body.write(str(val).encode("utf-8"))
            body.write(b"\r\n")

        body.write(f"--{boundary}--\r\n".encode("utf-8"))
        payload = body.getvalue()

        url = "https://www.searchapi.io/api/v1/search"
        req = urllib.request.Request(
            url,
            data=payload,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "DigitalShield-ForensicSearchApi/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                resp_bytes = resp.read()
                try:
                    resp_data = json.loads(resp_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as jde:
                    raise ReverseSearchProviderError(
                        f"Provider returned malformed or unparseable JSON response: {jde}"
                    )
                return self._parse_lens_response(resp_data)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            if e.code in (401, 403):
                raise ReverseSearchProviderError(
                    f"Gateway authentication failed (HTTP {e.code}). Please verify your reverse search API key."
                )
            elif e.code == 429:
                raise ReverseSearchProviderError(
                    f"Gateway rate limit reached or blocked (HTTP {e.code}). Please wait before retrying."
                )
            raise ReverseSearchProviderError(
                f"SearchApi gateway returned HTTP {e.code}: {e.reason}. Details: {err_body[:250]}"
            )
        except urllib.error.URLError as e:
            raise ReverseSearchProviderError(
                f"Network error contacting SearchApi gateway: {e.reason}"
            )
        except ReverseSearchProviderError:
            raise
        except Exception as e:
            raise ReverseSearchProviderError(f"SearchApi search error: {e}")

    def _query_lens_gateway(self, image_path: Path, api_key: str) -> Dict[str, Any]:
        """
        Query SerpApi Google Lens engine via official 2-step protocol:
        Step 1: Upload original evidence image to https://serpapi.com/image via multipart POST to get image_id.
        Step 2: Query https://serpapi.com/search?engine=google_lens&image_id=<id>&api_key=<key>&hl=en&type=visual_matches via GET.
        """
        image_bytes, content_type, filename = self._prepare_image_bytes(image_path)

        # -------------------------------------------------------------
        # STEP 1: Upload image to SerpApi Image API
        # -------------------------------------------------------------
        boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
        body = io.BytesIO()

        # The image field must be named 'image'
        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(
            f'Content-Disposition: form-data; name="image"; filename="{filename}"\r\n'.encode("utf-8")
        )
        body.write(f"Content-Type: {content_type}\r\n\r\n".encode("utf-8"))
        body.write(image_bytes)
        body.write(b"\r\n")

        # Add api_key parameter in multipart body
        body.write(f"--{boundary}\r\n".encode("utf-8"))
        body.write(f'Content-Disposition: form-data; name="api_key"\r\n\r\n'.encode("utf-8"))
        body.write(str(api_key).encode("utf-8"))
        body.write(b"\r\n")

        body.write(f"--{boundary}--\r\n".encode("utf-8"))
        upload_payload = body.getvalue()

        upload_url = "https://serpapi.com/image"
        upload_req = urllib.request.Request(
            upload_url,
            data=upload_payload,
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "User-Agent": "DigitalShield-ForensicGoogleLens/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(upload_req, timeout=REQUEST_TIMEOUT) as upload_resp:
                resp_bytes = upload_resp.read()
                try:
                    upload_data = json.loads(resp_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as jde:
                    raise ReverseSearchProviderError(
                        f"Image upload gateway returned malformed JSON response: {jde}"
                    )
                image_id = upload_data.get("image_id")
                if not image_id or not isinstance(image_id, str):
                    raise ReverseSearchProviderError(
                        "Image upload succeeded but no valid image_id was returned by SerpApi gateway."
                    )
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            if e.code in (401, 403):
                raise ReverseSearchProviderError(
                    f"Gateway authentication failed during image upload (HTTP {e.code}). Please verify your reverse search API key."
                )
            elif e.code == 429:
                raise ReverseSearchProviderError(
                    f"Gateway rate limit reached or blocked during image upload (HTTP {e.code}). Please wait before retrying."
                )
            raise ReverseSearchProviderError(
                f"Google Lens image upload gateway returned HTTP {e.code}: {e.reason}. Details: {err_body[:250]}"
            )
        except urllib.error.URLError as e:
            raise ReverseSearchProviderError(
                f"Network error contacting Google Lens upload gateway: {e.reason}"
            )
        except ReverseSearchProviderError:
            raise
        except Exception as e:
            raise ReverseSearchProviderError(f"Google Lens image upload error: {e}")

        # -------------------------------------------------------------
        # STEP 2: Query Google Lens engine with image_id
        # -------------------------------------------------------------
        params = urllib.parse.urlencode({
            "engine": "google_lens",
            "image_id": image_id,
            "api_key": api_key,
            "hl": "en",
            "type": "visual_matches",
        })
        search_url = f"https://serpapi.com/search?{params}"

        search_req = urllib.request.Request(
            search_url,
            headers={
                "User-Agent": "DigitalShield-ForensicGoogleLens/1.0",
            },
            method="GET",
        )

        try:
            with urllib.request.urlopen(search_req, timeout=REQUEST_TIMEOUT) as search_resp:
                search_bytes = search_resp.read()
                try:
                    search_data = json.loads(search_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as jde:
                    raise ReverseSearchProviderError(
                        f"Search gateway returned malformed JSON response: {jde}"
                    )
                return self._parse_lens_response(search_data)
        except urllib.error.HTTPError as e:
            err_body = ""
            try:
                err_body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass
            if e.code in (401, 403):
                raise ReverseSearchProviderError(
                    f"Gateway authentication failed during search (HTTP {e.code}). Please verify your reverse search API key."
                )
            elif e.code == 429:
                raise ReverseSearchProviderError(
                    f"Gateway rate limit reached or blocked during search (HTTP {e.code}). Please wait before retrying."
                )
            raise ReverseSearchProviderError(
                f"Google Lens search gateway returned HTTP {e.code}: {e.reason}. Details: {err_body[:250]}"
            )
        except urllib.error.URLError as e:
            raise ReverseSearchProviderError(
                f"Network error contacting Google Lens search gateway: {e.reason}"
            )
        except ReverseSearchProviderError:
            raise
        except Exception as e:
            raise ReverseSearchProviderError(f"Google Lens search error: {e}")

    def _query_custom_endpoint(self, image_path: Path, endpoint: str) -> Dict[str, Any]:
        """Query a custom compliant Google Lens endpoint."""
        image_bytes, _, _ = self._prepare_image_bytes(image_path)
        req = urllib.request.Request(
            endpoint,
            data=image_bytes,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return self._parse_lens_response(data)
        except Exception as e:
            raise ReverseSearchProviderError(f"Error querying custom Google Lens endpoint: {e}")

    @staticmethod
    def _parse_lens_response(data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse raw Google Lens gateway response into DigitalShield standardized format.

        Key insight: SerpApi Google Lens response structure:
          - visual_matches[].link  → original SOURCE PAGE URL (e.g. reddit.com/..., wikipedia.org/...)
          - visual_matches[].thumbnail → Google-hosted thumbnail cache URL (encrypted-tbn*.gstatic.com)
          - visual_matches[].image → sometimes the direct image URL on the source site

        We MUST keep page URLs and thumbnail URLs separate so the service layer can:
        1. Store the original source page URL as source_url.
        2. Store the Google thumbnail as thumbnail_url (clearly labeled).
        3. Use the source page for Scrapling enrichment.
        4. Use the thumbnail for perceptual hash comparison (as the candidate image).
        """
        visual_matches = data.get("visual_matches", [])
        pages = []
        similar_images = []
        exact_images = []

        for m in visual_matches:
            # The 'link' field is the actual webpage on the publishing platform
            page_url = m.get("link") or m.get("url")
            if not page_url:
                continue

            # thumbnail is the Google-cached preview image; 'image' may be the actual source image
            thumbnail = m.get("thumbnail")
            source_image = m.get("image") or m.get("source_image")
            # Prefer the actual source image URL; fall back to thumbnail for hash comparison
            candidate_img = source_image or thumbnail

            if candidate_img:
                similar_images.append(candidate_img)

            pages.append({
                "url": page_url,
                "page_title": m.get("title") or m.get("source"),
                "full_images": [source_image] if source_image else [],
                "partial_images": [],
                "thumbnail": thumbnail,         # Google CDN thumbnail — NOT the publishing site
                "source_image": source_image,   # Actual image on publishing site if available
                "score": None,
                "position": m.get("position"),
            })

        # Parse exact matches if present
        for em in data.get("exact_matches", []):
            e_url = em.get("link") or em.get("url")
            e_thumbnail = em.get("thumbnail")
            e_source_img = em.get("image") or em.get("source_image")
            e_img = e_source_img or e_thumbnail
            if e_url:
                pages.append({
                    "url": e_url,
                    "page_title": em.get("title") or em.get("source"),
                    "full_images": [e_source_img] if e_source_img else [],
                    "partial_images": [],
                    "thumbnail": e_thumbnail,
                    "source_image": e_source_img,
                    "score": 1.0,
                    "position": em.get("position"),
                })
            if e_img:
                exact_images.append(e_img)

        # Also collect from organic_results (standard web search results that include image matches)
        for org in data.get("organic_results", []):
            o_url = org.get("link") or org.get("url")
            if not o_url:
                continue
            o_thumbnail = org.get("thumbnail")
            o_img = org.get("image")
            # Only include if organic result has an associated image
            if o_img or o_thumbnail:
                pages.append({
                    "url": o_url,
                    "page_title": org.get("title"),
                    "full_images": [o_img] if o_img else [],
                    "partial_images": [],
                    "thumbnail": o_thumbnail,
                    "source_image": o_img,
                    "score": None,
                    "position": org.get("position"),
                })
                if o_img:
                    similar_images.append(o_img)

        # Collect from related_content if image URLs present
        for rc in data.get("related_content", []):
            rc_url = rc.get("link") or rc.get("url")
            if not rc_url:
                continue
            rc_img = rc.get("thumbnail") or rc.get("image")
            pages.append({
                "url": rc_url,
                "page_title": rc.get("title"),
                "full_images": [],
                "partial_images": [],
                "thumbnail": rc_img,
                "source_image": None,
                "score": None,
                "position": None,
            })

        best_guess = []
        if "knowledge_graph" in data and isinstance(data["knowledge_graph"], dict):
            kg_title = data["knowledge_graph"].get("title")
            if kg_title:
                best_guess.append(kg_title)
            kg_sub = data["knowledge_graph"].get("subtitle")
            if kg_sub:
                best_guess.append(kg_sub)

        if "ai_overview" in data and isinstance(data["ai_overview"], dict):
            ai_title = data["ai_overview"].get("title") or data["ai_overview"].get("header")
            if ai_title and isinstance(ai_title, str):
                best_guess.append(ai_title)

        if "search_information" in data and isinstance(data["search_information"], dict):
            query = data["search_information"].get("query_displayed")
            if query:
                best_guess.append(query)

        # Deduplicate best guess labels preserving order
        dedup_labels = []
        for lbl in best_guess:
            if lbl and lbl not in dedup_labels:
                dedup_labels.append(lbl)

        return {
            "web_entities": [],
            "full_matching_image_urls": exact_images,
            "partial_matching_image_urls": [],
            "visually_similar_image_urls": similar_images,
            "pages_with_matching_images": pages,
            "best_guess_labels": dedup_labels,
        }
