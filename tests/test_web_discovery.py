"""
Tests for the Public Image / Video Source Discovery integration
(Google Cloud Vision Web Detection + Scrapling enrichment + perceptual hash comparison).

RULES:
- All API calls and network requests are mocked; no real API calls are made.
- No real evidence files are modified.
- Tests use synthetic/fixture images only.
"""

import io
import os
import queue
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch, PropertyMock

import pytest
from PIL import Image

# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _make_tiny_jpeg_bytes() -> bytes:
    """Create a tiny synthetic JPEG in memory."""
    buf = io.BytesIO()
    img = Image.new("RGB", (16, 16), color=(100, 150, 200))
    img.save(buf, format="JPEG")
    return buf.getvalue()


def _make_tiny_png_bytes() -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (16, 16), color=(200, 100, 50))
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_base_dir(tmp_path: Path) -> Path:
    """Create an isolated DigitalShield data dir for a test."""
    bd = tmp_path / ".digitalshield_data"
    bd.mkdir(parents=True, exist_ok=True)
    return bd


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

@pytest.fixture()
def base_dir(tmp_path):
    return _make_base_dir(tmp_path)


@pytest.fixture()
def evidence_setup(tmp_path, base_dir):
    """Create a real case + evidence using EvidenceManager with a synthetic JPEG."""
    from digitalshield.case_manager.manager import CaseManager
    from digitalshield.evidence.manager import EvidenceManager

    # Write synthetic evidence file
    img_path = tmp_path / "test_evidence.jpg"
    img_path.write_bytes(_make_tiny_jpeg_bytes())

    case_mgr = CaseManager(base_dir)
    case = case_mgr.create_case(
        name="WD Test Case",
        investigator="Test Investigator",
        description="Web Discovery test",
    )

    ev_mgr = EvidenceManager(base_dir)
    evidence = ev_mgr.import_evidence(img_path, case.case_id)
    return case, evidence, base_dir


# ──────────────────────────────────────────────────────────────────────────────
# VisionWebDetectionProvider Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestVisionWebDetectionProvider:

    def test_missing_api_key_raises_credential_error(self, tmp_path):
        from digitalshield.web_discovery.vision_provider import (
            CredentialError, VisionWebDetectionProvider,
        )
        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        with patch.dict(os.environ, {"DIGITALSHIELD_TESTING": "1"}, clear=True):
            os.environ.pop("GOOGLE_CLOUD_API_KEY", None)
            with pytest.raises(CredentialError, match="GOOGLE_CLOUD_API_KEY"):
                provider.search_web(img_path)

    def test_empty_api_key_raises_credential_error(self, tmp_path):
        from digitalshield.web_discovery.vision_provider import (
            CredentialError, VisionWebDetectionProvider,
        )
        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": ""}):
            with pytest.raises(CredentialError):
                provider.search_web(img_path)

    def test_api_key_never_logged_or_printed(self, tmp_path, capsys):
        """The API key must not appear in any stdout/stderr output."""
        from digitalshield.web_discovery.vision_provider import (
            CredentialError, VisionWebDetectionProvider,
        )
        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        fake_key = "SUPER_SECRET_KEY_SHOULD_NOT_APPEAR_IN_OUTPUT"

        import urllib.request, urllib.error, json
        mock_resp_data = json.dumps({
            "responses": [{"webDetection": {}}]
        }).encode()

        class FakeResponse:
            status = 200
            headers = {"content-type": "application/json"}
            def read(self): return mock_resp_data
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": fake_key}):
            with patch("urllib.request.urlopen", return_value=FakeResponse()):
                provider.search_web(img_path)

        captured = capsys.readouterr()
        assert fake_key not in captured.out
        assert fake_key not in captured.err

    def test_parse_web_detection_full(self):
        from digitalshield.web_discovery.vision_provider import VisionWebDetectionProvider
        web = {
            "fullMatchingImages": [{"url": "https://example.com/full.jpg"}],
            "partialMatchingImages": [{"url": "https://example.com/partial.jpg"}],
            "visuallySimilarImages": [{"url": "https://example.com/similar.jpg"}],
            "pagesWithMatchingImages": [
                {
                    "url": "https://example.com/page",
                    "pageTitle": "Test Page",
                    "partialMatchingImages": [{"url": "https://example.com/pm.jpg"}],
                    "fullMatchingImages": [{"url": "https://example.com/fm.jpg"}],
                    "score": 0.9,
                }
            ],
            "bestGuessLabels": [{"label": "Michael Jackson"}, {"label": "Singer"}],
            "webEntities": [{"entityId": "/m/123", "description": "Pop Star", "score": 0.95}],
        }
        result = VisionWebDetectionProvider._parse_web_detection(web)

        assert "https://example.com/full.jpg" in result["full_matching_image_urls"]
        assert "https://example.com/partial.jpg" in result["partial_matching_image_urls"]
        assert "https://example.com/similar.jpg" in result["visually_similar_image_urls"]
        assert result["pages_with_matching_images"][0]["url"] == "https://example.com/page"
        assert result["pages_with_matching_images"][0]["page_title"] == "Test Page"
        assert "Michael Jackson" in result["best_guess_labels"]
        assert result["web_entities"][0]["description"] == "Pop Star"

    def test_parse_web_detection_empty(self):
        from digitalshield.web_discovery.vision_provider import VisionWebDetectionProvider
        result = VisionWebDetectionProvider._parse_web_detection({})
        assert result["full_matching_image_urls"] == []
        assert result["partial_matching_image_urls"] == []
        assert result["pages_with_matching_images"] == []
        assert result["best_guess_labels"] == []

    def test_api_error_403_raises_vision_api_error(self, tmp_path):
        from digitalshield.web_discovery.vision_provider import VisionAPIError, VisionWebDetectionProvider
        import urllib.error

        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        err = urllib.error.HTTPError(
            url="https://vision.googleapis.com/v1/images:annotate",
            code=403,
            msg="Forbidden",
            hdrs={},
            fp=io.BytesIO(b'{"error": {"code": 403, "message": "Access denied"}}'),
        )

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": "test-key"}):
            with patch("urllib.request.urlopen", side_effect=err):
                with pytest.raises(VisionAPIError, match="403"):
                    provider.search_web(img_path)

    def test_api_error_429_raises_vision_api_error(self, tmp_path):
        from digitalshield.web_discovery.vision_provider import VisionAPIError, VisionWebDetectionProvider
        import urllib.error

        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        err = urllib.error.HTTPError(
            url="", code=429, msg="Too Many Requests", hdrs={},
            fp=io.BytesIO(b"quota exceeded"),
        )
        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": "test-key"}):
            with patch("urllib.request.urlopen", side_effect=err):
                with pytest.raises(VisionAPIError, match="quota"):
                    provider.search_web(img_path)

    def test_api_level_credential_error_in_response(self, tmp_path):
        """Vision API may return credential error inside the JSON response body."""
        from digitalshield.web_discovery.vision_provider import CredentialError, VisionWebDetectionProvider
        import json

        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        body = json.dumps({
            "responses": [{"error": {"code": 7, "message": "Permission denied"}}]
        }).encode()

        class FakeResp:
            status = 200
            def read(self): return body
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": "bad-key"}):
            with patch("urllib.request.urlopen", return_value=FakeResp()):
                with pytest.raises(CredentialError):
                    provider.search_web(img_path)

    def test_mocked_successful_search(self, tmp_path):
        from digitalshield.web_discovery.vision_provider import VisionWebDetectionProvider
        import json

        provider = VisionWebDetectionProvider()
        img_path = tmp_path / "img.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        mock_resp_data = json.dumps({
            "responses": [{
                "webDetection": {
                    "pagesWithMatchingImages": [
                        {"url": "https://example.com/photo", "pageTitle": "Photo Page"}
                    ],
                    "bestGuessLabels": [{"label": "Pop Singer"}],
                }
            }]
        }).encode()

        class FakeResp:
            status = 200
            def read(self): return mock_resp_data
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": "test-key"}):
            with patch("urllib.request.urlopen", return_value=FakeResp()):
                result = provider.search_web(img_path)

        assert result["pages_with_matching_images"][0]["url"] == "https://example.com/photo"
        assert "Pop Singer" in result["best_guess_labels"]


# ──────────────────────────────────────────────────────────────────────────────
# Page Enricher Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestPageEnricher:

    def test_private_ip_blocked(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        result = enrich_page("http://192.168.1.1/page")
        assert result["retrieval_status"] == "PRIVATE_ADDRESS_BLOCKED"
        assert result["page_title"] is None

    def test_localhost_blocked(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        result = enrich_page("http://localhost/admin")
        assert result["retrieval_status"] == "PRIVATE_ADDRESS_BLOCKED"

    def test_normalize_url_dedup(self):
        from digitalshield.web_discovery.page_enricher import deduplicate_urls, normalize_url

        urls = [
            "https://Example.com/page/",
            "https://example.com/page",
            "HTTPS://EXAMPLE.COM/PAGE",
            "https://other.com/image.jpg",
        ]
        deduped = deduplicate_urls(urls)
        assert len(deduped) == 2  # first occurrence + other.com

    def test_fetch_failure_returns_status(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.return_value = "https://example.com/page"
        mock_client.fetch_public_url.side_effect = ValueError("Failed to fetch public URL 'https://example.com/page': Connection refused")

        result = enrich_page("https://example.com/page", client=mock_client)
        assert result["retrieval_status"] == "FETCH_FAILED"
        assert result["source_url"] == "https://example.com/page"

    def test_extracts_page_title_from_html(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        html_bytes = b"<html><head><title>Test Evidence Page</title></head><body></body></html>"
        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.return_value = "https://example.com/page"
        mock_client.fetch_public_url.return_value = (200, {"content-type": "text/html"}, html_bytes)
        mock_client.extract_public_metadata.return_value = {"source_title": "Test Evidence Page"}

        result = enrich_page("https://example.com/page", client=mock_client)
        assert result["retrieval_status"] == "RETRIEVED"
        assert result["page_title"] == "Test Evidence Page"

    def test_provider_title_preserved_without_fetch_override(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.return_value = "https://example.com/page"
        mock_client.fetch_public_url.return_value = (200, {"content-type": "text/html"}, b"<html></html>")
        mock_client.extract_public_metadata.return_value = {"source_title": "Scrapled Title"}

        result = enrich_page(
            "https://example.com/page",
            client=mock_client,
            provided_title="Provider Title",
        )
        # provided_title is used since page_title starts as provided_title
        assert result["page_title"] == "Provider Title"

    def test_oversized_response_returns_status(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.return_value = "https://example.com/img.jpg"
        mock_client.fetch_public_url.side_effect = ValueError("Oversized response: Content exceeds safe limit")

        result = enrich_page("https://example.com/img.jpg", client=mock_client)
        assert result["retrieval_status"] == "OVERSIZED"

    def test_image_url_used_as_media_url(self):
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.return_value = "https://cdn.example.com/photo.jpg"
        mock_client.fetch_public_url.return_value = (
            200, {"content-type": "image/jpeg"}, _make_tiny_jpeg_bytes()
        )
        result = enrich_page("https://cdn.example.com/photo.jpg", client=mock_client)
        assert result["media_url"] == "https://cdn.example.com/photo.jpg"

    def test_provided_media_url_validated_through_ssrf(self):
        """Provided media URLs that resolve to private IPs must be rejected."""
        from digitalshield.web_discovery.page_enricher import enrich_page
        from digitalshield.provenance.client import SafePublicClient

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.side_effect = [
            "https://example.com/page",  # page URL valid
            ValueError("Private address"),  # media URL blocked
        ]
        mock_client.fetch_public_url.return_value = (200, {"content-type": "text/html"}, b"<html></html>")
        mock_client.extract_public_metadata.return_value = {"source_title": None}

        result = enrich_page(
            "https://example.com/page",
            client=mock_client,
            provided_media_urls=["http://10.0.0.1/secret.jpg"],
        )
        assert result["media_url"] is None


# ──────────────────────────────────────────────────────────────────────────────
# WebDiscoveryService Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestWebDiscoveryService:

    def _make_mock_provider(self, web_data: dict = None):
        from digitalshield.web_discovery.vision_provider import VisionWebDetectionProvider
        provider = MagicMock(spec=VisionWebDetectionProvider)
        provider.search_web.return_value = web_data or {
            "web_entities": [],
            "full_matching_image_urls": [],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "best_guess_labels": [],
        }
        return provider

    def test_invalid_evidence_raises(self, base_dir):
        from digitalshield.web_discovery.service import WebDiscoveryService
        svc = WebDiscoveryService(base_dir=base_dir, provider=self._make_mock_provider())
        with pytest.raises(ValueError, match="does not exist"):
            svc.run_search("EVD-NONEXISTENT-000001")

    def test_missing_credentials_creates_session(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService
        from digitalshield.web_discovery.vision_provider import CredentialError

        case, evidence, base_dir = evidence_setup
        provider = MagicMock()
        provider.search_web.side_effect = CredentialError("GOOGLE_CLOUD_API_KEY not set")

        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "MISSING_CREDENTIALS"
        assert "GOOGLE_CLOUD_API_KEY" in session.error_message
        assert session.evidence_id == evidence.evidence_id

    def test_api_failure_creates_failed_session(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService
        from digitalshield.web_discovery.vision_provider import VisionAPIError

        case, evidence, base_dir = evidence_setup
        provider = MagicMock()
        provider.search_web.side_effect = VisionAPIError("Quota exceeded")

        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "FAILED"
        assert "Quota" in session.error_message

    def test_no_results_session(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        svc = WebDiscoveryService(base_dir=base_dir, provider=self._make_mock_provider())
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "NO_RESULTS"
        assert session.total_candidates == 0

    def test_successful_search_stores_results(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup

        web_data = {
            "web_entities": [{"entity_id": "/m/01", "description": "Test Entity", "score": 0.9}],
            "full_matching_image_urls": ["https://example.com/exact.jpg"],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [
                {
                    "url": "https://example.com/page",
                    "page_title": "Test Page",
                    "partial_images": [],
                    "full_images": ["https://example.com/exact.jpg"],
                    "score": 0.95,
                }
            ],
            "visually_similar_image_urls": [],
            "best_guess_labels": ["Test Subject"],
        }

        provider = self._make_mock_provider(web_data)

        # Mock page enricher to avoid real HTTP calls
        mock_enrich = MagicMock(return_value={
            "source_url": "https://example.com/page",
            "page_title": "Test Page",
            "domain": "example.com",
            "media_url": None,
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED",
            "notes": None,
        })

        with patch("digitalshield.web_discovery.service.enrich_page", mock_enrich):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            # Disable independent comparison (no real media to fetch)
            svc._compare_remote_image = MagicMock(return_value=(None, None))
            session = svc.run_search(evidence.evidence_id)

        assert session.status == "COMPLETED"
        assert session.total_candidates >= 1
        assert "Test Subject" in session.best_guess_labels

        results = svc.list_results_by_session(session.discovery_id)
        assert len(results) >= 1

        # Check results are stored in JSON store
        store_results = svc.store.list_web_discovery_results_by_session(session.discovery_id)
        assert len(store_results) >= 1

    def test_url_deduplication(self, evidence_setup):
        """Duplicate URLs returned by the API should produce only one result each."""
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup

        web_data = {
            "web_entities": [],
            "full_matching_image_urls": [
                "https://example.com/image.jpg",
                "https://example.com/image.jpg",  # duplicate
                "HTTPS://EXAMPLE.COM/IMAGE.JPG",  # same after normalization
            ],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "best_guess_labels": [],
        }

        provider = self._make_mock_provider(web_data)

        mock_enrich = MagicMock(return_value={
            "source_url": "https://example.com/image.jpg",
            "page_title": None,
            "domain": "example.com",
            "media_url": "https://example.com/image.jpg",
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED",
            "notes": None,
        })

        with patch("digitalshield.web_discovery.service.enrich_page", mock_enrich):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            svc._compare_remote_image = MagicMock(return_value=(None, None))
            session = svc.run_search(evidence.evidence_id)

        results = svc.list_results_by_session(session.discovery_id)
        # Should be 1 result despite 3 duplicate URLs
        assert len(results) == 1

    def test_video_evidence_returns_no_results_with_note(self, tmp_path, base_dir):
        """Video evidence must not trigger an API call; returns documented limitation."""
        from digitalshield.case_manager.manager import CaseManager
        from digitalshield.evidence.manager import EvidenceManager
        from digitalshield.web_discovery.service import WebDiscoveryService

        # Manufacture a video evidence record by writing an mp4 stub
        case_mgr = CaseManager(base_dir)
        case = case_mgr.create_case("Video Case", "Test Inv", "Video test")

        ev_mgr = EvidenceManager(base_dir)

        # Write a stub mp4 (not real video, but valid enough for import)
        mp4_path = tmp_path / "clip.mp4"
        mp4_path.write_bytes(b"\x00\x00\x00\x08ftyp" + b"\x00" * 100)

        # Patch mime detection to report video/mp4
        with patch.object(ev_mgr, "infer_mime_type", return_value="video/mp4"):
            with patch(
                "digitalshield.evidence.manager.EvidenceManager.infer_mime_type",
                staticmethod(lambda p: "video/mp4")
            ):
                # Use store directly to avoid mime guard
                from digitalshield.evidence.models import Evidence
                from datetime import datetime, timezone
                import hashlib

                sha = hashlib.sha256(mp4_path.read_bytes()).hexdigest()
                ev = Evidence(
                    evidence_id="EVD-2026-VIDEO001",
                    case_id=case.case_id,
                    original_filename="clip.mp4",
                    stored_filename="clip.mp4",
                    stored_path=str(mp4_path),
                    file_size=mp4_path.stat().st_size,
                    mime_type="video/mp4",
                    sha256=sha,
                )
                ev_mgr.store.save_evidence(ev.to_dict())

        provider = MagicMock()
        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        session = svc.run_search("EVD-2026-VIDEO001")

        # Provider must NOT have been called for video evidence
        provider.search_web.assert_not_called()
        assert session.is_video_evidence is True
        assert session.status == "NO_RESULTS"
        assert "video frame" in (session.video_search_note or "").lower()

    def test_original_evidence_not_modified(self, evidence_setup):
        """Running web discovery must never alter the preserved evidence file."""
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        vault_path = Path(evidence.stored_path)
        original_bytes = vault_path.read_bytes()
        original_mtime = vault_path.stat().st_mtime

        provider = self._make_mock_provider()
        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        svc.run_search(evidence.evidence_id)

        assert vault_path.read_bytes() == original_bytes
        assert vault_path.stat().st_mtime == original_mtime

    def test_session_and_results_persisted_in_store(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        web_data = {
            "web_entities": [],
            "full_matching_image_urls": [],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [
                {"url": "https://photos.example.com/1", "page_title": "Photo 1",
                 "partial_images": [], "full_images": [], "score": 0.8}
            ],
            "visually_similar_image_urls": [],
            "best_guess_labels": [],
        }
        provider = self._make_mock_provider(web_data)
        mock_enrich = MagicMock(return_value={
            "source_url": "https://photos.example.com/1",
            "page_title": "Photo 1",
            "domain": "photos.example.com",
            "media_url": None,
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED",
            "notes": None,
        })

        with patch("digitalshield.web_discovery.service.enrich_page", mock_enrich):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            svc._compare_remote_image = MagicMock(return_value=(None, None))
            session = svc.run_search(evidence.evidence_id)

        # Retrieve from store
        stored_session = svc.store.get_web_discovery_session(session.discovery_id)
        assert stored_session is not None
        assert stored_session["evidence_id"] == evidence.evidence_id

        stored_results = svc.store.list_web_discovery_results_by_session(session.discovery_id)
        assert len(stored_results) >= 1

    def test_provider_match_type_in_result(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        web_data = {
            "web_entities": [],
            "full_matching_image_urls": ["https://cdn.example.com/photo.jpg"],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "best_guess_labels": [],
        }

        provider = self._make_mock_provider(web_data)
        mock_enrich = MagicMock(return_value={
            "source_url": "https://cdn.example.com/photo.jpg",
            "page_title": None, "domain": "cdn.example.com",
            "media_url": "https://cdn.example.com/photo.jpg",
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED", "notes": None,
        })

        with patch("digitalshield.web_discovery.service.enrich_page", mock_enrich):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            svc._compare_remote_image = MagicMock(return_value=(None, None))
            session = svc.run_search(evidence.evidence_id)

        results = svc.list_results_by_session(session.discovery_id)
        assert any(r.provider_match_type == "EXACT_MATCH" for r in results)

    def test_independent_similarity_distinct_from_provider(self, evidence_setup):
        """Independent similarity must be clearly distinguished from provider score."""
        from digitalshield.web_discovery.service import WebDiscoveryService
        from digitalshield.web_discovery.models import WebDiscoveryResult

        case, evidence, base_dir = evidence_setup
        web_data = {
            "web_entities": [],
            "full_matching_image_urls": [],
            "partial_matching_image_urls": [],
            "pages_with_matching_images": [
                {"url": "https://example.com/p", "page_title": "P", "score": 0.9,
                 "partial_images": [], "full_images": ["https://cdn.example.com/img.jpg"]}
            ],
            "visually_similar_image_urls": [],
            "best_guess_labels": [],
        }

        provider = self._make_mock_provider(web_data)
        mock_enrich = MagicMock(return_value={
            "source_url": "https://example.com/p",
            "page_title": "P", "domain": "example.com",
            "media_url": "https://cdn.example.com/img.jpg",
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED", "notes": None,
        })

        with patch("digitalshield.web_discovery.service.enrich_page", mock_enrich):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            # Return a specific independent score
            svc._compare_remote_image = MagicMock(return_value=(0.7543, "pHash + aHash + dHash (independently calculated by DigitalShield)"))
            session = svc.run_search(evidence.evidence_id)

        results = svc.list_results_by_session(session.discovery_id)
        page_result = next((r for r in results if r.source_url == "https://example.com/p"), None)
        assert page_result is not None
        # Provider score (0.9) ≠ independent score (0.7543)
        assert page_result.provider_score == pytest.approx(0.9, abs=1e-6)
        assert page_result.independent_similarity_score == pytest.approx(0.7543, abs=1e-4)
        assert "independently calculated" in (page_result.independent_matching_method or "")

    def test_result_status_labels(self):
        from digitalshield.web_discovery.service import WebDiscoveryService
        assert WebDiscoveryService._result_status("EXACT_MATCH", None) == "Source discovered"
        assert WebDiscoveryService._result_status("PARTIAL_MATCH", None) == "Source discovered"
        assert WebDiscoveryService._result_status("VISUALLY_SIMILAR", None) == "Potential media match"
        assert WebDiscoveryService._result_status("VISUALLY_SIMILAR", 0.9) == "Potential media match"
        assert WebDiscoveryService._result_status("PAGE_WITH_IMAGE", None) == "Awaiting investigator review"

    def test_limitations_in_session(self, evidence_setup):
        """Every session must carry forensic limitations."""
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        provider = self._make_mock_provider()
        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        session = svc.run_search(evidence.evidence_id)

        assert len(session.limitations) >= 2
        # Must mention that it doesn't index every site
        combined = " ".join(session.limitations).lower()
        assert "index" in combined or "every" in combined

    def test_audit_event_logged_on_success(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService

        case, evidence, base_dir = evidence_setup
        provider = self._make_mock_provider()
        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        svc.run_search(evidence.evidence_id)

        events = svc.audit_logger.get_events_by_case(case.case_id)
        actions = [e.get("action") for e in events]
        assert any("WEB_DISCOVERY" in a for a in actions)

    def test_audit_event_logged_on_credential_error(self, evidence_setup):
        from digitalshield.web_discovery.service import WebDiscoveryService
        from digitalshield.web_discovery.vision_provider import CredentialError

        case, evidence, base_dir = evidence_setup
        provider = MagicMock()
        provider.search_web.side_effect = CredentialError("No key")

        svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
        svc.run_search(evidence.evidence_id)

        events = svc.audit_logger.get_events_by_case(case.case_id)
        actions = [e.get("action") for e in events]
        assert "WEB_DISCOVERY_CREDENTIAL_ERROR" in actions


# ──────────────────────────────────────────────────────────────────────────────
# JSON Store Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestJSONStoreWebDiscovery:

    def test_save_and_retrieve_session(self, base_dir):
        from digitalshield.storage.json_store import JSONStore

        store = JSONStore(base_dir)
        session = {
            "discovery_id": "WDS-2026-000001",
            "evidence_id": "EVD-2026-000001",
            "case_id": "DS-2026-000001",
            "status": "COMPLETED",
            "provider": "Google Cloud Vision Web Detection",
            "search_timestamp": "2026-10-27T00:00:00+00:00",
            "total_candidates": 5,
            "results_count": 5,
            "best_guess_labels": [],
            "is_video_evidence": False,
            "video_search_note": None,
            "limitations": [],
            "error_message": None,
        }
        store.save_web_discovery_session(session)
        retrieved = store.get_web_discovery_session("WDS-2026-000001")
        assert retrieved is not None
        assert retrieved["status"] == "COMPLETED"

    def test_save_and_retrieve_result(self, base_dir):
        from digitalshield.storage.json_store import JSONStore

        store = JSONStore(base_dir)
        result = {
            "result_id": "WDR-2026-000001",
            "discovery_id": "WDS-2026-000001",
            "evidence_id": "EVD-2026-000001",
            "case_id": "DS-2026-000001",
            "source_url": "https://example.com/page",
            "page_title": "Example",
            "domain": "example.com",
            "media_url": None,
            "provider_match_type": "PAGE_WITH_IMAGE",
            "provider_score": 0.8,
            "independent_similarity_score": None,
            "independent_matching_method": None,
            "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
            "retrieval_status": "RETRIEVED",
            "status": "Awaiting investigator review",
            "notes": None,
            "limitations": [],
        }
        store.save_web_discovery_result(result)
        retrieved = store.get_web_discovery_result("WDR-2026-000001")
        assert retrieved is not None
        assert retrieved["source_url"] == "https://example.com/page"

    def test_list_by_session_and_case(self, base_dir):
        from digitalshield.storage.json_store import JSONStore

        store = JSONStore(base_dir)
        for i in range(3):
            store.save_web_discovery_result({
                "result_id": f"WDR-2026-{i:06d}",
                "discovery_id": "WDS-2026-000001",
                "evidence_id": "EVD-2026-000001",
                "case_id": "DS-2026-CASE01",
                "source_url": f"https://example.com/r{i}",
                "page_title": None, "domain": "example.com", "media_url": None,
                "provider_match_type": "PAGE_WITH_IMAGE",
                "provider_score": None, "independent_similarity_score": None,
                "independent_matching_method": None,
                "retrieval_timestamp": "2026-10-27T00:00:00+00:00",
                "retrieval_status": "RETRIEVED",
                "status": "Awaiting investigator review",
                "notes": None, "limitations": [],
            })
        by_session = store.list_web_discovery_results_by_session("WDS-2026-000001")
        assert len(by_session) == 3

        by_case = store.list_web_discovery_results_by_case("DS-2026-CASE01")
        assert len(by_case) == 3


# ──────────────────────────────────────────────────────────────────────────────
# Reporting Integration Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestWebDiscoveryReporting:

    def _make_full_report_data(self, tmp_path, base_dir):
        """Create a case + evidence + web discovery session for reporting tests."""
        from digitalshield.case_manager.manager import CaseManager
        from digitalshield.evidence.manager import EvidenceManager
        from digitalshield.reporting.service import ReportingService
        from digitalshield.storage.json_store import JSONStore

        img_path = tmp_path / "ev.jpg"
        img_path.write_bytes(_make_tiny_jpeg_bytes())

        case_mgr = CaseManager(base_dir)
        case = case_mgr.create_case("Report WD Test", "Test Inv", "Reporting test")

        ev_mgr = EvidenceManager(base_dir)
        evidence = ev_mgr.import_evidence(img_path, case.case_id)

        store = JSONStore(base_dir)
        session = {
            "discovery_id": "WDS-2026-000001",
            "evidence_id": evidence.evidence_id,
            "case_id": case.case_id,
            "status": "COMPLETED",
            "provider": "Google Cloud Vision Web Detection",
            "search_timestamp": "2026-10-27T09:00:00+00:00",
            "total_candidates": 2,
            "results_count": 2,
            "best_guess_labels": ["Famous Person"],
            "is_video_evidence": False,
            "video_search_note": None,
            "limitations": ["Test limitation"],
            "error_message": None,
        }
        store.save_web_discovery_session(session)
        store.save_web_discovery_result({
            "result_id": "WDR-2026-000001",
            "discovery_id": "WDS-2026-000001",
            "evidence_id": evidence.evidence_id,
            "case_id": case.case_id,
            "source_url": "https://example.com/photo",
            "page_title": "Celebrity Photo",
            "domain": "example.com",
            "media_url": "https://cdn.example.com/photo.jpg",
            "provider_match_type": "EXACT_MATCH",
            "provider_score": 0.98,
            "independent_similarity_score": 0.9234,
            "independent_matching_method": "pHash + aHash + dHash (independently calculated by DigitalShield)",
            "retrieval_timestamp": "2026-10-27T09:01:00+00:00",
            "retrieval_status": "RETRIEVED",
            "status": "Source discovered",
            "notes": None,
            "limitations": ["Provider-reported score reflects Google's index."],
        })
        return case, evidence, base_dir

    def test_report_data_includes_web_discovery(self, tmp_path, base_dir):
        from digitalshield.reporting.service import ReportingService

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)

        assert len(data.web_discovery_sessions) >= 1
        assert len(data.web_discovery_results) >= 1
        sess = data.web_discovery_sessions[0]
        assert sess["discovery_id"] == "WDS-2026-000001"

    def test_markdown_report_includes_web_discovery_section(self, tmp_path, base_dir):
        from digitalshield.reporting.service import ReportingService
        from digitalshield.reporting.renderers.markdown_renderer import MarkdownRenderer

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)
        md = MarkdownRenderer.render(data)

        assert "Public Image / Video Source Discovery" in md
        assert "Google Cloud Vision Web Detection" in md
        assert "WDS-2026-000001" in md
        assert "https://example.com/photo" in md
        assert "EXACT_MATCH" in md
        assert "0.9234" in md
        assert "independently calculated" in md.lower()
        # Must contain limitations notice
        assert "Limitation" in md

    def test_html_report_includes_web_discovery_section(self, tmp_path, base_dir):
        from digitalshield.reporting.service import ReportingService
        from digitalshield.reporting.renderers.html_renderer import HTMLRenderer

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)
        html = HTMLRenderer.render(data)

        assert "Public Image / Video Source Discovery" in html
        assert "WDS-2026-000001" in html
        assert "example.com" in html

    def test_pdf_report_generates_without_error(self, tmp_path, base_dir):
        from digitalshield.reporting.service import ReportingService

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        record, file_map = svc.generate_report(case.case_id, formats=["pdf"])

        pdf_path = file_map.get("pdf")
        assert pdf_path is not None
        assert Path(str(pdf_path)).exists()
        assert Path(str(pdf_path)).stat().st_size > 0

    def test_overall_findings_includes_web_discovery_summary(self, tmp_path, base_dir):
        from digitalshield.reporting.service import ReportingService

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)

        found = any("Web Detection" in f or "web discovery" in f.lower() for f in data.overall_findings)
        assert found, f"Expected web discovery summary in overall_findings: {data.overall_findings}"

    def test_provider_url_distinct_from_investigator_url(self, tmp_path, base_dir):
        """Investigator-entered URLs (reported_source_url) must remain separate from discovered URLs."""
        from digitalshield.reporting.service import ReportingService

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)

        # The investigator URL field should be None/empty (no investigator URL was supplied)
        # The web_discovery_results should contain the discovered URL
        assert data.reported_source_url is None or data.reported_source_url != "https://example.com/photo"
        discovered_urls = [r["source_url"] for r in data.web_discovery_results]
        assert "https://example.com/photo" in discovered_urls

    def test_existing_report_sections_preserved(self, tmp_path, base_dir):
        """Adding web discovery must not remove any pre-existing report sections."""
        from digitalshield.reporting.service import ReportingService
        from digitalshield.reporting.renderers.markdown_renderer import MarkdownRenderer

        case, evidence, base_dir = self._make_full_report_data(tmp_path, base_dir)
        svc = ReportingService(base_dir)
        data = svc.compile_report_data(case.case_id)
        md = MarkdownRenderer.render(data)

        required_sections = [
            "Case Overview",
            "Evidence Inventory",
            "Error Level Analysis",
            "Deepfake",
            "Audit Trail",
            "Forensic",
            "Investigator",
        ]
        for section in required_sections:
            assert section in md, f"Required section '{section}' missing from markdown report"


# ──────────────────────────────────────────────────────────────────────────────
# Web Discovery Worker Thread Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestWebDiscoveryWorker:

    def test_worker_emits_complete_message(self, evidence_setup):
        """Worker must emit wd_complete with session and results."""
        from digitalshield.gui.workers import WebDiscoveryWorker
        from digitalshield.web_discovery.vision_provider import VisionWebDetectionProvider

        case, evidence, base_dir = evidence_setup
        q: queue.Queue = queue.Queue()

        mock_session = MagicMock()
        mock_session.discovery_id = "WDS-2026-000001"
        mock_session.to_dict.return_value = {
            "discovery_id": "WDS-2026-000001",
            "status": "NO_RESULTS",
        }

        with patch(
            "digitalshield.web_discovery.service.WebDiscoveryService.run_search",
            return_value=mock_session
        ):
            with patch(
                "digitalshield.web_discovery.service.WebDiscoveryService.list_results_by_session",
                return_value=[]
            ):
                worker = WebDiscoveryWorker(
                    evidence_id=evidence.evidence_id,
                    msg_queue=q,
                    base_dir=base_dir,
                )
                worker.start()
                worker.join(timeout=5)

        messages = []
        while not q.empty():
            messages.append(q.get_nowait())

        types = [m["type"] for m in messages]
        assert "wd_start" in types
        assert "wd_complete" in types

    def test_worker_emits_error_on_exception(self, base_dir):
        """Worker must emit wd_error when an exception occurs."""
        from digitalshield.gui.workers import WebDiscoveryWorker

        q: queue.Queue = queue.Queue()

        with patch(
            "digitalshield.web_discovery.service.WebDiscoveryService.run_search",
            side_effect=RuntimeError("Test error")
        ):
            worker = WebDiscoveryWorker(
                evidence_id="EVD-NONEXISTENT",
                msg_queue=q,
                base_dir=base_dir,
            )
            worker.start()
            worker.join(timeout=5)

        messages = []
        while not q.empty():
            messages.append(q.get_nowait())

        types = [m["type"] for m in messages]
        assert "wd_error" in types

    def test_worker_is_daemon_thread(self, base_dir):
        """Worker thread must be a daemon so it doesn't block app shutdown."""
        from digitalshield.gui.workers import WebDiscoveryWorker
        q: queue.Queue = queue.Queue()
        worker = WebDiscoveryWorker("EVD-X", q, base_dir)
        assert worker.daemon is True
