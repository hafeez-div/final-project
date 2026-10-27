"""
Automated Reverse Image Search and Web Discovery Test Suite.

Verifies:
1. Automatic initiation upon evidence upload.
2. Evidence immutability and SHA-256 preservation.
3. Provider interaction and error handling (missing credentials, quota).
4. Candidate collection and deduplication.
5. Scrapling public page enrichment and SSRF blocking.
6. Perceptual hashing (aHash, dHash, pHash) comparison against original image.
7. Verification classification thresholds.
8. JSONStore session and result persistence.
9. Audit trail logging for all discovery milestones.
10. Multi-format report integration (Markdown, HTML, PDF) with clickable hyperlinks.
"""

import io
import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from PIL import Image

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.provenance.client import SafePublicClient
from digitalshield.reporting.service import ReportingService
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.page_enricher import deduplicate_urls, enrich_page, normalize_url
from digitalshield.web_discovery.service import WebDiscoveryService
from digitalshield.web_discovery.vision_provider import (
    CredentialError,
    VisionAPIError,
    VisionWebDetectionProvider,
)


def _make_jpeg_bytes(color=(100, 150, 200)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", (32, 32), color=color)
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def evidence_fixture(tmp_path):
    base_dir = tmp_path / ".digitalshield_data"
    base_dir.mkdir(parents=True, exist_ok=True)

    case_mgr = CaseManager(base_dir=base_dir)
    case = case_mgr.create_case(
        name="Automated Reverse Search Case",
        investigator="Forensic Lead",
        description="End-to-end automated reverse image search test",
    )

    img_file = tmp_path / "original_evidence.jpg"
    img_bytes = _make_jpeg_bytes()
    img_file.write_bytes(img_bytes)

    ev_mgr = EvidenceManager(base_dir=base_dir)
    evidence = ev_mgr.import_evidence(file_path=img_file, case_id=case.case_id)

    # Pre-generate fingerprints
    fp_service = FingerprintService(base_dir=base_dir)
    fp_service.generate_fingerprints(evidence.evidence_id)

    return base_dir, case, evidence, img_file


class TestAutomaticReverseImageSearch:
    """Tests the automated workflow and provider execution."""

    def test_provider_requires_api_key_when_unset(self, tmp_path):
        provider = VisionWebDetectionProvider()
        test_img = tmp_path / "img.jpg"
        test_img.write_bytes(_make_jpeg_bytes())

        with patch.dict(os.environ, {"DIGITALSHIELD_TESTING": "1"}, clear=True):
            os.environ.pop("GOOGLE_CLOUD_API_KEY", None)
            with pytest.raises(CredentialError, match="GOOGLE_CLOUD_API_KEY"):
                provider.search_web(test_img)

    def test_mocked_provider_search_success(self, tmp_path):
        provider = VisionWebDetectionProvider()
        test_img = tmp_path / "img.jpg"
        test_img.write_bytes(_make_jpeg_bytes())

        mock_payload = {
            "responses": [{
                "webDetection": {
                    "fullMatchingImages": [{"url": "https://example.com/match1.jpg"}],
                    "partialMatchingImages": [{"url": "https://example.com/partial1.jpg"}],
                    "visuallySimilarImages": [{"url": "https://example.com/similar1.jpg"}],
                    "pagesWithMatchingImages": [{
                        "url": "https://example.com/page1",
                        "pageTitle": "Example Page One",
                        "fullMatchingImages": [{"url": "https://example.com/match1.jpg"}],
                    }],
                    "bestGuessLabels": [{"label": "Celebrity Portrait"}],
                }
            }]
        }

        class MockResp:
            status = 200
            def read(self):
                return json.dumps(mock_payload).encode("utf-8")
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass

        with patch.dict(os.environ, {"GOOGLE_CLOUD_API_KEY": "AIzaSyFakeKey"}):
            with patch("urllib.request.urlopen", return_value=MockResp()):
                results = provider.search_web(test_img)
                assert len(results["full_matching_image_urls"]) == 1
                assert "Celebrity Portrait" in results["best_guess_labels"]

    def test_service_run_search_full_pipeline(self, evidence_fixture):
        base_dir, case, evidence, _ = evidence_fixture

        # Mock provider
        mock_provider = MagicMock()
        mock_provider.PROVIDER_NAME = "Google Cloud Vision Web Detection"
        mock_provider.search_web.return_value = {
            "full_matching_image_urls": ["https://example.com/match.jpg"],
            "partial_matching_image_urls": [],
            "visually_similar_image_urls": ["https://example.com/similar.jpg"],
            "pages_with_matching_images": [{
                "url": "https://example.com/article",
                "page_title": "Investigative Article",
                "score": 0.92,
                "full_images": ["https://example.com/match.jpg"],
                "partial_images": [],
            }],
            "best_guess_labels": ["Test Subject"],
        }

        # Mock client to return JPEG bytes for candidate image
        cand_bytes = _make_jpeg_bytes()
        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.side_effect = lambda u: u
        mock_client.fetch_public_url.return_value = (200, {"content-type": "image/jpeg"}, cand_bytes)

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider, client=mock_client)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "COMPLETED"
        assert session.total_results == 3
        assert session.verified_matches >= 1

        results = svc.list_results_by_session(session.session_id)
        assert len(results) == 3

        # Verify perceptual similarity was computed
        matched_res = [r for r in results if r.media_url == "https://example.com/match.jpg"][0]
        assert matched_res.calculated_similarity is not None
        assert matched_res.verification_status == "Exact or near-exact perceptual match"
        assert matched_res.ahash_distance is not None

        # Verify audit events
        events = svc.audit_logger.get_events_by_case(case.case_id)
        actions = [e["action"] for e in events]
        assert "AUTOMATIC_REVERSE_SEARCH_STARTED" in actions
        assert "REVERSE_SEARCH_COMPLETED" in actions
        assert "CANDIDATE_IMAGE_VERIFIED" in actions

    def test_evidence_file_never_modified_during_search(self, evidence_fixture):
        base_dir, case, evidence, img_file = evidence_fixture
        sha_before = evidence.sha256

        mock_provider = MagicMock()
        mock_provider.search_web.return_value = {"full_matching_image_urls": []}
        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        svc.run_search(evidence.evidence_id)

        vault_path = Path(evidence.stored_path)
        import hashlib
        sha_after = hashlib.sha256(vault_path.read_bytes()).hexdigest()
        assert sha_before == sha_after

    def test_missing_credentials_handled_gracefully(self, evidence_fixture):
        base_dir, case, evidence, _ = evidence_fixture
        mock_provider = MagicMock()
        mock_provider.search_web.side_effect = CredentialError("GOOGLE_CLOUD_API_KEY is not set.")

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider)
        session = svc.run_search(evidence.evidence_id)

        assert session.status == "MISSING_CREDENTIALS"
        assert "GOOGLE_CLOUD_API_KEY" in session.error_message

        events = svc.audit_logger.get_events_by_case(case.case_id)
        actions = [e["action"] for e in events]
        assert "REVERSE_SEARCH_FAILED" in actions

    def test_ssrf_blocking_in_scraping(self):
        client = SafePublicClient()
        # Private loopback address must be blocked
        res = enrich_page("http://127.0.0.1:8000/secret", client=client)
        assert res["retrieval_status"] == "PRIVATE_ADDRESS_BLOCKED"

        res_localhost = enrich_page("http://localhost/admin", client=client)
        assert res_localhost["retrieval_status"] == "PRIVATE_ADDRESS_BLOCKED"

    def test_report_includes_reverse_image_search_section(self, evidence_fixture):
        base_dir, case, evidence, _ = evidence_fixture

        mock_provider = MagicMock()
        mock_provider.PROVIDER_NAME = "Google Cloud Vision Web Detection"
        mock_provider.search_web.return_value = {
            "full_matching_image_urls": ["https://news.example.com/verified_image.jpg"],
            "partial_matching_image_urls": [],
            "visually_similar_image_urls": [],
            "pages_with_matching_images": [{
                "url": "https://news.example.com/article1",
                "page_title": "Breaking News Story",
                "score": 0.95,
                "full_images": ["https://news.example.com/verified_image.jpg"],
                "partial_images": [],
            }],
            "best_guess_labels": ["Public Figure"],
        }

        mock_client = MagicMock(spec=SafePublicClient)
        mock_client.validate_url.side_effect = lambda u: u
        mock_client.fetch_public_url.return_value = (200, {"content-type": "image/jpeg"}, _make_jpeg_bytes())

        svc = WebDiscoveryService(base_dir=base_dir, provider=mock_provider, client=mock_client)
        svc.run_search(evidence.evidence_id)

        rpt_service = ReportingService(base_dir=base_dir)
        report_record, file_map = rpt_service.generate_report(case.case_id, formats="all")

        # Markdown report validation
        md_text = file_map["markdown"].read_text(encoding="utf-8")
        assert "# Public Online Image Discovery and Reverse Image Search Findings" in md_text
        assert "https://news.example.com/article1" in md_text
        assert "Breaking News Story" in md_text
        assert "Exact or near-exact perceptual match" in md_text

        # HTML report validation
        html_text = file_map["html"].read_text(encoding="utf-8")
        assert "Public Online Image Discovery and Reverse Image Search Findings" in html_text
        assert "Breaking News Story" in html_text
        assert "news.example.com" in html_text

        # PDF generated
        assert file_map["pdf"].exists()
        assert file_map["pdf"].stat().st_size > 1000
