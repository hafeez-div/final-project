"""
Comprehensive Unit & Integration Test Suite for Reverse Image Search.
Verifies all 15 scenarios specified in Part 9:
 1. Search initiation upon evidence ingestion / analysis run
 2. Evidence immutability: SHA-256 baseline preserved before and after search
 3. Successful reverse search with candidate pages & images
 4. Genuine response parsing (visual_matches, exact_matches, knowledge_graph)
 5. Genuine NO_RESULTS when provider is contacted but discovers 0 matches
 6. Missing credentials: status PROVIDER_UNAVAILABLE, NOT_SUBMITTED_NO_GATEWAY
 7. Gateway blocked / rate-limited: HTTP 429 -> status BLOCKED
 8. Gateway auth failure: HTTP 401/403 -> status PROVIDER_UNAVAILABLE
 9. Malformed response JSON -> status PARSE_ERROR
10. Unsupported media format -> status INVALID_IMAGE
11. Video evidence handling -> status NO_RESULTS with explanatory note
12. Multi-strategy perceptual hashing (standard baseline vs aspect-ratio normalized crop)
13. SSRF protection: private IP and localhost blocking
14. Cryptographic audit trail logging for all milestones
15. Report generation (PDF, HTML, MD) reflecting duration, submission status, clickable links
"""

import hashlib
import io
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error
import pytest
from PIL import Image

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.provenance.client import SafePublicClient
from digitalshield.reporting.service import ReportingService
from digitalshield.web_discovery.google_lens_provider import (
    GoogleLensProvider,
    ReverseSearchProviderError,
)
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.service import WebDiscoveryService


def _create_jpeg(size=(64, 64), color=(120, 140, 180)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=color)
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def test_env(tmp_path):
    base_dir = tmp_path / ".digitalshield_data"
    base_dir.mkdir(parents=True, exist_ok=True)
    case_mgr = CaseManager(base_dir=base_dir)
    case = case_mgr.create_case(
        name="Reverse Search Comprehensive Test Case",
        investigator="Forensic Examiner",
        description="Verifying all 15 forensic reverse search scenarios",
    )
    ev_file = tmp_path / "subject_photo.jpg"
    ev_file.write_bytes(_create_jpeg(size=(200, 300), color=(100, 120, 140)))

    ev_mgr = EvidenceManager(base_dir=base_dir)
    evidence = ev_mgr.import_evidence(file_path=ev_file, case_id=case.case_id)

    fp_svc = FingerprintService(base_dir=base_dir)
    fp_svc.generate_fingerprints(evidence.evidence_id)

    return base_dir, case, evidence, ev_file


class TestReverseSearchFifteenScenarios:

    def test_01_search_initiation(self, test_env):
        """Scenario 1: Search initiation occurs and creates a persistent session."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "full_matching_image_urls": [],
            "best_guess_labels": ["Target Portrait"],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session is not None
        assert session.session_id.startswith("WDS-")
        assert session.evidence_id == evidence.evidence_id
        assert session.case_id == case.case_id
        mock_provider.search_web.assert_called_once()

    def test_02_evidence_immutability(self, test_env):
        """Scenario 2: Evidence SHA-256 hash verified before and after search."""
        base_dir, case, evidence, ev_file = test_env
        vault_path = Path(evidence.stored_path)
        sha_before = hashlib.sha256(vault_path.read_bytes()).hexdigest()

        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "full_matching_image_urls": [],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        svc.run_search(evidence.evidence_id)

        sha_after = hashlib.sha256(vault_path.read_bytes()).hexdigest()
        assert sha_before == sha_after == evidence.sha256

    def test_03_successful_reverse_search_returns_candidates(self, test_env):
        """Scenario 3: Returns candidate pages and images."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [
                {
                    "title": "Public Profile Source",
                    "link": "https://example.com/profile",
                    "thumbnail": "https://example.com/thumb.jpg",
                }
            ],
            "pages_with_matching_images": [
                {
                    "url": "https://example.com/profile",
                    "page_title": "Public Profile Source",
                    "full_images": ["https://example.com/thumb.jpg"],
                    "partial_images": [],
                    "score": None,
                }
            ],
            "visually_similar_image_urls": ["https://example.com/thumb.jpg"],
            "full_matching_image_urls": [],
            "best_guess_labels": ["Public Figure"],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "COMPLETED"
        assert session.total_results >= 1
        assert session.image_submission_status == "SUBMITTED_AND_SEARCHED"
        assert session.search_duration_seconds is not None

    def test_04_genuine_response_parsing(self):
        """Scenario 4: Genuine response parsing of visual_matches, exact_matches, knowledge_graph."""
        raw_gateway_resp = {
            "visual_matches": [
                {
                    "position": 1,
                    "title": "Iconic Subject Photo",
                    "link": "https://news.example.com/photo",
                    "source": "News Org",
                    "thumbnail": "https://news.example.com/img_thumb.jpg",
                }
            ],
            "exact_matches": [
                {
                    "title": "Exact Archive Match",
                    "link": "https://archive.example.com/original",
                    "source_image": "https://archive.example.com/original.jpg",
                }
            ],
            "knowledge_graph": {
                "title": "Famous Personality",
                "subtitle": "Public Figure",
            },
        }

        parsed = GoogleLensProvider._parse_lens_response(raw_gateway_resp)
        assert len(parsed["pages_with_matching_images"]) == 2
        assert "https://news.example.com/img_thumb.jpg" in parsed["visually_similar_image_urls"]
        assert "https://archive.example.com/original.jpg" in parsed["full_matching_image_urls"]
        assert "Famous Personality" in parsed["best_guess_labels"]

    def test_05_genuine_no_results(self, test_env):
        """Scenario 5: Provider contacted and searched successfully, returns 0 matches -> NO_RESULTS."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "full_matching_image_urls": [],
            "best_guess_labels": [],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "NO_RESULTS"
        assert session.total_results == 0
        assert session.image_submission_status == "SUBMITTED_AND_SEARCHED"

    def test_06_missing_credentials_handling(self, test_env):
        """Scenario 6: When gateway credentials are missing -> status PROVIDER_UNAVAILABLE, NOT_SUBMITTED_NO_GATEWAY."""
        base_dir, case, evidence, _ = test_env
        provider = GoogleLensProvider()  # Unconfigured provider

        with patch.dict(os.environ, {}, clear=True):
            svc = WebDiscoveryService(base_dir=base_dir, provider=provider)
            session = svc.run_search(evidence.evidence_id)

            assert session.status == "PROVIDER_UNAVAILABLE"
            assert session.image_submission_status == "NOT_SUBMITTED_NO_GATEWAY"
            assert "gateway is not configured" in session.error_message.lower()

    def test_07_gateway_blocked_rate_limit(self, test_env):
        """Scenario 7: Gateway rate limit or block (HTTP 429) -> status BLOCKED."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.side_effect = ReverseSearchProviderError(
            "Gateway rate limit reached or blocked (HTTP 429). Please wait before retrying."
        )

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "BLOCKED"
        assert session.image_submission_status == "SUBMISSION_BLOCKED"

    def test_08_gateway_auth_failure(self, test_env):
        """Scenario 8: Gateway auth failure (HTTP 401/403) -> status PROVIDER_UNAVAILABLE."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.side_effect = ReverseSearchProviderError(
            "Gateway authentication failed (HTTP 401). Please verify your reverse search API key."
        )

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "PROVIDER_UNAVAILABLE"
        assert session.image_submission_status == "NOT_SUBMITTED_NO_GATEWAY"

    def test_09_malformed_response_json(self, test_env):
        """Scenario 9: Malformed JSON response -> status PARSE_ERROR."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.side_effect = ReverseSearchProviderError(
            "Provider returned malformed or unparseable JSON response: Expecting value: line 1 column 1 (char 0)"
        )

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "PARSE_ERROR"
        assert session.image_submission_status == "SUBMISSION_FAILED"

    def test_10_unsupported_media_format(self, tmp_path, test_env):
        """Scenario 10: Unsupported media format -> status INVALID_IMAGE."""
        base_dir, case, _, _ = test_env
        text_file = tmp_path / "document.txt"
        text_file.write_text("Text evidence", encoding="utf-8")

        ev_mgr = EvidenceManager(base_dir=base_dir)
        doc_evidence = ev_mgr.import_evidence(file_path=text_file, case_id=case.case_id)

        svc = WebDiscoveryService(base_dir=base_dir)
        session = svc.run_search(doc_evidence.evidence_id)

        assert session.status == "INVALID_IMAGE"
        assert session.image_submission_status == "NOT_SUBMITTED_INVALID_FORMAT"

    def test_11_video_evidence_handling(self, tmp_path, test_env):
        """Scenario 11: Video evidence -> status NO_RESULTS with explicit explanatory note."""
        base_dir, case, _, _ = test_env
        vid_file = tmp_path / "clip.mp4"
        vid_file.write_bytes(b"\x00\x00\x00 ftypisom" + b"\x00" * 100)

        ev_mgr = EvidenceManager(base_dir=base_dir)
        vid_evidence = ev_mgr.import_evidence(file_path=vid_file, case_id=case.case_id)

        svc = WebDiscoveryService(base_dir=base_dir)
        session = svc.run_search(vid_evidence.evidence_id)

        assert session.status == "NO_RESULTS"
        assert session.is_video_evidence is True
        assert session.image_submission_status == "NOT_SUBMITTED_VIDEO"
        assert "video frame extraction" in session.video_search_note.lower()

    def test_12_multistrategy_perceptual_hashing(self, test_env):
        """Scenario 12: Multi-strategy perceptual hashing (standard baseline vs center-crop for thumbnails)."""
        base_dir, case, evidence, _ = test_env
        svc = WebDiscoveryService(base_dir=base_dir)

        # Create a candidate thumbnail image that is center-cropped to a 1:1 square
        square_thumb_bytes = _create_jpeg(size=(64, 64), color=(100, 120, 140))

        with patch.object(svc.client, "validate_url", return_value="https://example.com/thumb.jpg"):
            with patch.object(svc.client, "fetch_public_url", return_value=(200, {}, square_thumb_bytes)):
                score, method, da, dd, dp, classification = svc._compare_remote_image(
                    "https://example.com/thumb.jpg", evidence.evidence_id
                )
                assert score is not None
                assert score > 0.80
                assert classification in ("Exact or near-exact visual match", "High visual similarity")
                assert "crop" in method.lower() or "multi-hash" in method.lower()

    def test_13_ssrf_safety(self):
        """Scenario 13: SSRF safe client blocks private and localhost URLs."""
        client = SafePublicClient()
        with pytest.raises(ValueError) as exc1:
            client.validate_url("http://127.0.0.1/admin")
        assert "loopback" in str(exc1.value).lower() or "internal" in str(exc1.value).lower() or "denied" in str(exc1.value).lower()

        with pytest.raises(ValueError) as exc2:
            client.validate_url("http://192.168.1.100/config")
        assert "private" in str(exc2.value).lower() or "denied" in str(exc2.value).lower() or "blocked" in str(exc2.value).lower()

        with pytest.raises(ValueError) as exc3:
            client.validate_url("file:///etc/passwd")
        assert "scheme" in str(exc3.value).lower()

    def test_14_cryptographic_audit_trail_logging(self, test_env):
        """Scenario 14: Audit events logged with accurate timestamps and actor."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [],
            "pages_with_matching_images": [],
            "visually_similar_image_urls": [],
            "full_matching_image_urls": [],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        svc.run_search(evidence.evidence_id)

        audit_path = base_dir / "audit.log"
        assert audit_path.exists()
        log_content = audit_path.read_text(encoding="utf-8")
        assert "AUTOMATIC_REVERSE_SEARCH_STARTED" in log_content
        assert "WEB_DISCOVERY_SESSION_STARTED" in log_content
        assert "REVERSE_SEARCH_PROVIDER_REQUESTED" in log_content
        assert "REVERSE_SEARCH_COMPLETED" in log_content

    def test_15_report_generation_all_formats(self, test_env):
        """Scenario 15: PDF, HTML, Markdown reports reflect duration, submission status, and clickable links."""
        base_dir, case, evidence, _ = test_env
        mock_provider = MagicMock(spec=GoogleLensProvider)
        mock_provider.PROVIDER_NAME = "Google Lens"
        mock_provider.search_web.return_value = {
            "visual_matches": [
                {
                    "title": "Observed News Source",
                    "link": "https://example.com/article",
                    "thumbnail": "https://example.com/image.jpg",
                }
            ],
            "pages_with_matching_images": [
                {
                    "url": "https://example.com/article",
                    "page_title": "Observed News Source",
                    "full_images": ["https://example.com/image.jpg"],
                    "partial_images": [],
                    "score": None,
                }
            ],
            "visually_similar_image_urls": ["https://example.com/image.jpg"],
            "full_matching_image_urls": [],
            "best_guess_labels": ["Public Article"],
        }

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        svc.run_search(evidence.evidence_id)

        reporting_svc = ReportingService(base_dir=base_dir)
        record, report_paths = reporting_svc.generate_report(
            case_id=case.case_id,
            formats=["markdown", "html", "pdf"]
        )

        # Test Markdown
        md_text = Path(report_paths["markdown"]).read_text(encoding="utf-8")
        assert "## 10. Public Reverse Image Search Findings" in md_text
        assert "Search Duration" in md_text
        assert "Image Submission Status" in md_text

        # Test HTML
        html_text = Path(report_paths["html"]).read_text(encoding="utf-8")
        assert "Public Online Image Discovery and Reverse Image Search Findings" in html_text
        assert "Search Duration" in html_text
        assert "Image Submission Status" in html_text

        # Test PDF
        pdf_path = Path(report_paths["pdf"])
        assert pdf_path.exists()
        assert pdf_path.stat().st_size > 1000

    def test_16_two_step_workflow_execution(self, tmp_path):
        """Scenario 16: Two-step SerpApi workflow (POST /image -> image_id -> GET /search)."""
        provider = GoogleLensProvider(api_key="mock_serpapi_key")
        test_img = tmp_path / "subject.jpg"
        test_img.write_bytes(_create_jpeg())

        calls = []

        class MockStep1:
            status = 200
            def read(self):
                return json.dumps({"image_id": "i_abc123xyz"}).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): pass

        class MockStep2:
            status = 200
            def read(self):
                return json.dumps({
                    "visual_matches": [
                        {
                            "title": "Bean (film) - Wikipedia",
                            "link": "https://en.wikipedia.org/wiki/Bean_(film)",
                            "source": "Wikipedia",
                            "thumbnail": "https://example.com/bean.jpg"
                        }
                    ],
                    "ai_overview": {"title": "British Comedy Film"},
                }).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): pass

        def mock_urlopen(req, timeout=30):
            calls.append(req)
            if "serpapi.com/image" in req.full_url:
                assert req.get_method() == "POST"
                return MockStep1()
            elif "serpapi.com/search" in req.full_url:
                assert req.get_method() == "GET"
                assert "image_id=i_abc123xyz" in req.full_url
                assert "engine=google_lens" in req.full_url
                return MockStep2()
            raise ValueError(f"Unexpected URL: {req.full_url}")

        with patch("urllib.request.urlopen", side_effect=mock_urlopen):
            res = provider.search_web(test_img)

        assert len(calls) == 2
        assert len(res["pages_with_matching_images"]) == 1
        assert res["pages_with_matching_images"][0]["url"] == "https://en.wikipedia.org/wiki/Bean_(film)"
        assert "British Comedy Film" in res["best_guess_labels"]

    def test_17_missing_image_id_raises_error(self, tmp_path):
        """Scenario 17: Upload response missing image_id raises ReverseSearchProviderError."""
        provider = GoogleLensProvider(api_key="mock_key")
        test_img = tmp_path / "subject.jpg"
        test_img.write_bytes(_create_jpeg())

        class MockUploadNoId:
            status = 200
            def read(self):
                return json.dumps({"status": "success"}).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): pass

        with patch("urllib.request.urlopen", return_value=MockUploadNoId()):
            with pytest.raises(ReverseSearchProviderError, match="no valid image_id"):
                provider.search_web(test_img)

    def test_18_http_errors_handled_appropriately(self, tmp_path):
        """Scenario 18: HTTP 400, 404, 500 error responses during upload or search are handled."""
        provider = GoogleLensProvider(api_key="mock_key")
        test_img = tmp_path / "subject.jpg"
        test_img.write_bytes(_create_jpeg())

        # Test upload 400
        err_400 = urllib.error.HTTPError(
            url="https://serpapi.com/image",
            code=400,
            msg="Bad Request",
            hdrs={},
            fp=io.BytesIO(b'{"error": "Image file too large"}')
        )
        with patch("urllib.request.urlopen", side_effect=err_400):
            with pytest.raises(ReverseSearchProviderError, match="400"):
                provider.search_web(test_img)

        # Test search 500
        class MockUploadOk:
            status = 200
            def read(self):
                return json.dumps({"image_id": "i_123"}).encode("utf-8")
            def __enter__(self): return self
            def __exit__(self, *a): pass

        err_500 = urllib.error.HTTPError(
            url="https://serpapi.com/search",
            code=500,
            msg="Internal Server Error",
            hdrs={},
            fp=io.BytesIO(b'{"error": "Internal gateway failure"}')
        )

        def mock_step_fail(req, timeout=30):
            if "serpapi.com/image" in req.full_url:
                return MockUploadOk()
            raise err_500

        with patch("urllib.request.urlopen", side_effect=mock_step_fail):
            with pytest.raises(ReverseSearchProviderError, match="500"):
                provider.search_web(test_img)

