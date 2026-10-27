"""
Google Cloud Vision Web Detection Provider for DigitalShield.

SECURITY RULES:
- API key is read exclusively from the GOOGLE_CLOUD_API_KEY environment variable.
- The key is NEVER logged, printed, displayed in the GUI, or sent to any third party.
- The key is sent only to vision.googleapis.com over HTTPS.
- Operates strictly on read-only evidence vault copies; never modifies original evidence.
- All results are presented as probabilistic indicators, never absolute truth.

ETHICAL RULES:
- Defensive forensics only; no exploitation, credential harvesting, or surveillance.
- Only public HTTP/HTTPS resources are accessed; no authentication bypass.
- Results use neutral language: 'Candidate source', 'Potential match'.

LIMITATIONS (documented per project rules):
- This API does not guarantee coverage of every website on the internet.
- Results depend on Google's index and may not reflect the current state of the web.
- Provider similarity scores are probabilistic and not cryptographic proof of anything.
- Video frame search is NOT YET IMPLEMENTED; image-only search is performed.
"""

import base64
import io
import json
import os
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from PIL import Image

from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider

VISION_API_ENDPOINT = "https://vision.googleapis.com/v1/images:annotate"
REQUEST_TIMEOUT = 30  # seconds
MAX_IMAGE_BYTES = 20 * 1024 * 1024   # 20 MB (Vision API limit)
RESIZE_THRESHOLD = 10 * 1024 * 1024  # Resize if >10 MB before sending


class CredentialError(Exception):
    """Raised when the GOOGLE_CLOUD_API_KEY environment variable is missing or empty."""


class VisionAPIError(Exception):
    """Raised when the Vision API returns an error."""


class VisionWebDetectionProvider(BaseReverseImageProvider):
    """
    Calls the Google Cloud Vision Web Detection REST API using the
    GOOGLE_CLOUD_API_KEY environment variable.

    NEVER hard-codes, logs, or exposes the API key.
    """

    PROVIDER_NAME = "Google Cloud Vision Web Detection"

    def __init__(self):
        # Read key at call time (not at module import) to respect test patching
        pass

    @staticmethod
    def _load_env_file_if_present() -> None:
        """
        Check for .env file in current directory or project root and load GOOGLE_CLOUD_API_KEY
        if it is not explicitly configured in os.environ.
        If GOOGLE_CLOUD_API_KEY is present in os.environ (even if empty, indicating an explicit test/override),
        do NOT read from disk.
        """
        if "GOOGLE_CLOUD_API_KEY" in os.environ:
            return

        # Skip loading from disk in test environments
        if os.environ.get("DIGITALSHIELD_TESTING") == "1":
            return

        search_paths = [
            Path.cwd() / ".env",
            Path.cwd().parent / ".env",
            Path("C:/Users/student/final-project/.env"),
            Path("C:/Users/student/Documents/final year/.env"),
        ]
        for p in search_paths:
            if p.exists() and p.is_file():
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith("GOOGLE_CLOUD_API_KEY="):
                                val = line.split("=", 1)[1].strip().strip('"').strip("'")
                                if val:
                                    os.environ["GOOGLE_CLOUD_API_KEY"] = val
                                    return
                except Exception:
                    pass

    @classmethod
    def _get_api_key(cls) -> str:
        """
        Retrieve API key strictly from environment.
        Raises CredentialError with a helpful message if missing.
        """
        cls._load_env_file_if_present()
        key = os.environ.get("GOOGLE_CLOUD_API_KEY", "").strip()
        if not key:
            raise CredentialError(
                "GOOGLE_CLOUD_API_KEY environment variable is not set or is empty.\n"
                "To configure it on Windows:\n"
                "  setx GOOGLE_CLOUD_API_KEY \"your-key-here\"\n"
                "Then restart the application.\n"
                "See the README for Google Cloud billing and quota information."
            )
        return key

    @staticmethod
    def _prepare_image_bytes(image_path: Path) -> bytes:
        """
        Load image from the read-only evidence vault and prepare bytes for the API.
        Resizes to stay within Vision API size limits.
        Does NOT modify the original file.
        """
        with open(image_path, "rb") as f:
            raw_bytes = f.read()

        if len(raw_bytes) > RESIZE_THRESHOLD:
            # Resize in memory only — never touch the vault file
            with Image.open(io.BytesIO(raw_bytes)) as img:
                img.thumbnail((2000, 2000), Image.LANCZOS)
                buf = io.BytesIO()
                fmt = img.format or "JPEG"
                img.save(buf, format=fmt)
                raw_bytes = buf.getvalue()

        if len(raw_bytes) > MAX_IMAGE_BYTES:
            raise ValueError(
                f"Image ({len(raw_bytes) // 1024} KB) exceeds the Vision API limit "
                f"of {MAX_IMAGE_BYTES // (1024*1024)} MB even after resizing."
            )

        return raw_bytes

    def search_web(self, image_path: Path) -> Dict[str, Any]:
        """
        Submit image to Google Cloud Vision Web Detection and return parsed results.

        Returns a dict with keys:
            web_entities, full_matching_image_urls, partial_matching_image_urls,
            pages_with_matching_images (list of {url, page_title?, partial_images?, full_images?}),
            visually_similar_image_urls, best_guess_labels
        All keys always present; empty lists when no results.

        Raises CredentialError for missing key.
        Raises VisionAPIError for API-level errors (billing, quota, invalid key).
        Raises ValueError / OSError for local file or network failures.
        """
        api_key = self._get_api_key()

        image_bytes = self._prepare_image_bytes(image_path)
        b64_content = base64.b64encode(image_bytes).decode("ascii")

        request_body = {
            "requests": [
                {
                    "image": {"content": b64_content},
                    "features": [{"type": "WEB_DETECTION", "maxResults": 100}]
                }
            ]
        }

        url = f"{VISION_API_ENDPOINT}?key={api_key}"
        body_bytes = json.dumps(request_body).encode("utf-8")

        req = urllib.request.Request(
            url,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DigitalShield-ForensicWebDiscovery/1.0",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
                response_text = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                pass

            # Detect billing / quota / auth errors specifically
            if e.code == 403:
                raise VisionAPIError(
                    f"Vision API returned HTTP 403 Forbidden. "
                    f"Check that billing is enabled and the key is restricted to the Cloud Vision API. "
                    f"Details: {body[:300]}"
                )
            if e.code == 429:
                raise VisionAPIError(
                    f"Vision API quota exceeded (HTTP 429). "
                    f"Review your Google Cloud quota limits. Details: {body[:300]}"
                )
            if e.code == 400:
                raise VisionAPIError(
                    f"Vision API returned HTTP 400 Bad Request. "
                    f"Details: {body[:300]}"
                )
            raise VisionAPIError(
                f"Vision API returned HTTP {e.code}: {e.reason}. Details: {body[:300]}"
            )
        except urllib.error.URLError as e:
            raise VisionAPIError(
                f"Network error contacting Vision API: {e.reason}. "
                f"Check your internet connection."
            )
        except Exception as e:
            raise VisionAPIError(f"Unexpected error during Vision API call: {e}")

        try:
            response = json.loads(response_text)
        except json.JSONDecodeError as e:
            raise VisionAPIError(f"Invalid JSON response from Vision API: {e}")

        # Check for API-level error block
        responses = response.get("responses", [])
        if not responses:
            raise VisionAPIError("Vision API returned an empty responses array.")

        first = responses[0]
        if "error" in first:
            err = first["error"]
            code = err.get("code", "")
            msg = err.get("message", "Unknown API error")
            if code in (7, 16):
                raise CredentialError(
                    f"Vision API credentials error (code {code}): {msg}. "
                    f"Ensure GOOGLE_CLOUD_API_KEY is valid and Cloud Vision API is enabled."
                )
            raise VisionAPIError(f"Vision API error (code {code}): {msg}")

        web = first.get("webDetection", {})
        return self._parse_web_detection(web)

    @staticmethod
    def _parse_web_detection(web: Dict) -> Dict[str, Any]:
        """Parse the webDetection block from Vision API response into a structured dict."""

        def _urls(items: List[dict], key: str = "url") -> List[str]:
            return [item.get(key, "") for item in items if item.get(key)]

        pages = []
        for page in web.get("pagesWithMatchingImages", []):
            page_url = page.get("url", "")
            if not page_url:
                continue
            entry = {
                "url": page_url,
                "page_title": page.get("pageTitle"),
                "partial_images": _urls(page.get("partialMatchingImages", [])),
                "full_images": _urls(page.get("fullMatchingImages", [])),
                "score": page.get("score"),
            }
            pages.append(entry)

        best_guess = [
            label.get("label", "")
            for label in web.get("bestGuessLabels", [])
            if label.get("label")
        ]

        entities = [
            {
                "entity_id": e.get("entityId", ""),
                "description": e.get("description", ""),
                "score": e.get("score"),
            }
            for e in web.get("webEntities", [])
            if e.get("description")
        ]

        return {
            "web_entities": entities,
            "full_matching_image_urls": _urls(web.get("fullMatchingImages", [])),
            "partial_matching_image_urls": _urls(web.get("partialMatchingImages", [])),
            "pages_with_matching_images": pages,
            "visually_similar_image_urls": _urls(web.get("visuallySimilarImages", [])),
            "best_guess_labels": best_guess,
        }
