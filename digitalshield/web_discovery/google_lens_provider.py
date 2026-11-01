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
from typing import Any, Dict, List, Optional

from PIL import Image

from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider

REQUEST_TIMEOUT = 30  # seconds
MAX_IMAGE_BYTES = 20 * 1024 * 1024   # 20 MB limit
RESIZE_THRESHOLD = 10 * 1024 * 1024  # Resize in-memory if >10 MB


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

    @staticmethod
    def _prepare_image_bytes(image_path: Path) -> bytes:
        """
        Load image from read-only evidence vault and prepare bytes.
        Resizes in-memory if exceeding threshold; never modifies original file.
        """
        with open(image_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) > RESIZE_THRESHOLD:
            with Image.open(io.BytesIO(raw_bytes)) as img:
                img.thumbnail((2000, 2000), Image.LANCZOS)
                buf = io.BytesIO()
                fmt = img.format or "JPEG"
                img.save(buf, format=fmt)
                raw_bytes = buf.getvalue()

        if len(raw_bytes) > MAX_IMAGE_BYTES:
            raise ValueError(
                f"Image ({len(raw_bytes) // 1024} KB) exceeds the safe limit "
                f"of {MAX_IMAGE_BYTES // (1024 * 1024)} MB."
            )
        return raw_bytes

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
        image_bytes = self._prepare_image_bytes(image_path)
        boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
        body = io.BytesIO()

        filename = image_path.name
        content_type = "image/jpeg"
        if filename.lower().endswith(".png"):
            content_type = "image/png"
        elif filename.lower().endswith(".webp"):
            content_type = "image/webp"

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
        image_bytes = self._prepare_image_bytes(image_path)

        # -------------------------------------------------------------
        # STEP 1: Upload image to SerpApi Image API
        # -------------------------------------------------------------
        boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
        body = io.BytesIO()

        filename = image_path.name
        content_type = "image/jpeg"
        if filename.lower().endswith(".png"):
            content_type = "image/png"
        elif filename.lower().endswith(".webp"):
            content_type = "image/webp"

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
        image_bytes = self._prepare_image_bytes(image_path)
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
        """
        visual_matches = data.get("visual_matches", [])
        pages = []
        similar_images = []
        exact_images = []

        for m in visual_matches:
            page_url = m.get("link") or m.get("url")
            if not page_url:
                continue

            img_url = m.get("thumbnail") or m.get("source_image") or m.get("image")
            img_list = [img_url] if img_url else []
            if img_url:
                similar_images.append(img_url)

            pages.append({
                "url": page_url,
                "page_title": m.get("title") or m.get("source"),
                "full_images": img_list,
                "partial_images": [],
                "score": None,  # Provider does not give a calibrated float
            })

        # Also parse exact matches if present
        for em in data.get("exact_matches", []):
            e_url = em.get("link") or em.get("url")
            e_img = em.get("thumbnail") or em.get("source_image") or em.get("image")
            if e_url:
                pages.append({
                    "url": e_url,
                    "page_title": em.get("title") or em.get("source"),
                    "full_images": [e_img] if e_img else [],
                    "partial_images": [],
                    "score": 1.0,
                })
            if e_img:
                exact_images.append(e_img)

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
