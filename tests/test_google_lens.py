"""
Tests for DigitalShield Google Lens Reverse Image Search Integration
(Investigator-Assisted Public Reverse Image Search).

RULES:
- All external browser-opening calls are mocked.
- No real evidence files are modified.
- Full offline test suite without paid API keys or live network requests.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.web_discovery.lens_models import (
    GOOGLE_LENS_CATEGORIES,
    GoogleLensResult,
    GoogleLensSession,
    detect_platform_name,
    validate_http_url,
)
from digitalshield.web_discovery.lens_service import (
    GOOGLE_LENS_URL,
    GoogleLensService,
)


@pytest.fixture
def test_env(tmp_path):
    """Setup an isolated case and evidence in temporary storage."""
    base_dir = tmp_path / ".digitalshield_data"
    base_dir.mkdir(parents=True, exist_ok=True)

    case_mgr = CaseManager(base_dir=base_dir)
    case = case_mgr.create_case(
        name="Google Lens Investigation",
        investigator="Agent Forensic",
        description="Testing manual Google Lens reverse image search workflow",
    )

    # Create dummy image
    img_file = tmp_path / "test_photo.jpg"
    img_file.write_bytes(b"\xFF\xD8\xFF\xE0" + b"\x00" * 100)

    ev_mgr = EvidenceManager(base_dir=base_dir)
    evidence = ev_mgr.import_evidence(file_path=img_file, case_id=case.case_id)

    return base_dir, case, evidence


class TestGoogleLensModels:
    """Test URL validations, category enums, and platform detections."""

    def test_valid_http_and_https_urls(self):
        assert validate_http_url("https://instagram.com/p/123") == "https://instagram.com/p/123"
        assert validate_http_url("http://example.com/image.jpg") == "http://example.com/image.jpg"

    def test_invalid_scheme_rejected(self):
        with pytest.raises(ValueError, match="must use http:// or https://"):
            validate_http_url("file:///etc/passwd")

        with pytest.raises(ValueError, match="must use http:// or https://"):
            validate_http_url("ftp://ftp.example.com/image.png")

        with pytest.raises(ValueError, match="cannot be empty"):
            validate_http_url("")

    def test_platform_name_detection(self):
        assert detect_platform_name("https://www.instagram.com/p/ABC") == "Instagram"
        assert detect_platform_name("https://x.com/user/status/123") == "X (Twitter)"
        assert detect_platform_name("https://reddit.com/r/pics/comments/xyz") == "Reddit"
        assert detect_platform_name("https://en.wikipedia.org/wiki/Michael_Jackson") == "Wikipedia"
        assert detect_platform_name("https://news.bbc.co.uk/article") == "news.bbc.co.uk"

    def test_result_model_validation(self):
        res = GoogleLensResult(
            result_id="GLR-2026-000001",
            session_id="GLS-2026-000001",
            evidence_id="EVD-2026-000001",
            case_id="DS-2026-000001",
            source_url="https://example.com/article",
            search_category="Exact image match",
        )
        assert res.platform_name == "Web Source"
        assert res.search_category == "Exact image match"
        assert res.search_provider == "Google Lens (Manual)"

    def test_result_model_rejects_file_urls(self):
        with pytest.raises(ValueError):
            GoogleLensResult(
                result_id="GLR-2026-000001",
                session_id="GLS-2026-000001",
                evidence_id="EVD-2026-000001",
                case_id="DS-2026-000001",
                source_url="file:///C:/secrets.txt",
            )


class TestGoogleLensService:
    """Test session lifecycle, browser opening, and result recording."""

    def test_initiate_lens_search_opens_portal_and_creates_session(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open") as mock_open:
            session, vault_path = service.initiate_lens_search(evidence.evidence_id)

            assert session.status == "ACTIVE"
            assert session.evidence_id == evidence.evidence_id
            assert session.case_id == case.case_id
            assert session.results_count == 0
            assert vault_path.exists()
            assert mock_open.called
            assert mock_open.call_args[0][0] == GOOGLE_LENS_URL

    def test_initiate_lens_search_logs_audit_event(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        events = service.audit_logger.get_events_by_case(case.case_id)
        initiated_events = [e for e in events if e.get("action") == "GOOGLE_LENS_SEARCH_INITIATED"]
        assert len(initiated_events) == 1
        assert initiated_events[0]["details"]["session_id"] == session.session_id

    def test_record_single_matching_result(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        result = service.record_match_result(
            session_id=session.session_id,
            source_url="https://www.instagram.com/p/photoid123",
            page_title="Public Post Photo",
            media_url="https://scontent.cdninstagram.com/photo.jpg",
            search_category="Exact image match",
            investigator_notes="Verified visual match on public feed.",
        )

        assert result.result_id.startswith("GLR-")
        assert result.platform_name == "Instagram"
        assert result.search_category == "Exact image match"
        assert result.investigator_notes == "Verified visual match on public feed."

        # Verify persisted under session
        results = service.list_results_by_session(session.session_id)
        assert len(results) == 1
        assert results[0]["source_url"] == "https://www.instagram.com/p/photoid123"

        # Verify audit log recorded
        events = service.audit_logger.get_events_by_case(case.case_id)
        rec_events = [e for e in events if e.get("action") == "GOOGLE_LENS_RESULT_RECORDED"]
        assert len(rec_events) == 1
        assert rec_events[0]["details"]["result_id"] == result.result_id

    def test_record_multiple_matching_results(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        service.record_match_result(
            session_id=session.session_id,
            source_url="https://reddit.com/r/pics/1",
            search_category="Visually similar image",
        )
        service.record_match_result(
            session_id=session.session_id,
            source_url="https://pinterest.com/pin/2",
            search_category="Cropped or edited image",
        )
        service.record_match_result(
            session_id=session.session_id,
            source_url="https://x.com/status/3",
            search_category="Social-media result",
        )

        results = service.list_results_by_session(session.session_id)
        assert len(results) == 3
        platforms = [r["platform_name"] for r in results]
        assert "Reddit" in platforms
        assert "Pinterest" in platforms
        assert "X (Twitter)" in platforms

    def test_record_invalid_url_raises(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        with pytest.raises(ValueError, match="must use http:// or https://"):
            service.record_match_result(
                session_id=session.session_id,
                source_url="file:///C:/Users/student/evidence.jpg",
            )

    def test_mark_session_no_results(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        updated_session = service.mark_session_no_results(
            session.session_id,
            notes="No public reverse image matches discovered on Google Lens.",
        )
        assert updated_session.status == "NO_RESULTS"
        assert "No public reverse image matches" in updated_session.investigator_notes

        events = service.audit_logger.get_events_by_case(case.case_id)
        no_res_events = [e for e in events if e.get("action") == "GOOGLE_LENS_NO_RESULTS_RECORDED"]
        assert len(no_res_events) == 1

    def test_original_evidence_file_remains_unmodified(self, test_env):
        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        vault_path = Path(evidence.stored_path)
        sha_before = evidence.sha256

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        service.record_match_result(
            session_id=session.session_id,
            source_url="https://example.com/match",
        )

        import hashlib
        sha_after = hashlib.sha256(vault_path.read_bytes()).hexdigest()
        assert sha_before == sha_after


class TestGoogleLensReporting:
    """Test report generation inclusion of Google Lens findings."""

    def test_report_includes_google_lens_section(self, test_env):
        from digitalshield.reporting.service import ReportingService

        base_dir, case, evidence = test_env
        service = GoogleLensService(base_dir=base_dir)

        with patch("webbrowser.open"):
            session, _ = service.initiate_lens_search(evidence.evidence_id)

        service.record_match_result(
            session_id=session.session_id,
            source_url="https://wikipedia.org/wiki/Test_Subject",
            platform_name="Wikipedia",
            page_title="Test Subject Biography",
            search_category="Exact image match",
            investigator_notes="Confirmed visual identity match.",
        )

        rpt_service = ReportingService(base_dir=base_dir)
        report_record, file_map = rpt_service.generate_report(case.case_id, formats="all")

        assert "markdown" in file_map
        assert "html" in file_map
        assert "pdf" in file_map

        # Check Markdown content
        md_text = file_map["markdown"].read_text(encoding="utf-8")
        assert "## 10. Public Reverse Image Search Findings – Google Lens" in md_text
        assert "Wikipedia" in md_text
        assert "https://wikipedia.org/wiki/Test_Subject" in md_text
        assert "Manual Google Lens search" in md_text

        # Check HTML content
        html_text = file_map["html"].read_text(encoding="utf-8")
        assert "Public Reverse Image Search Findings &ndash; Google Lens" in html_text
        assert "Wikipedia" in html_text
        assert "https://wikipedia.org/wiki/Test_Subject" in html_text

        # Check PDF generated without error
        assert file_map["pdf"].exists()
        assert file_map["pdf"].stat().st_size > 1000
