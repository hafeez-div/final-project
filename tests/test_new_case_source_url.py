"""
Unit and regression tests for Public Source URL Input in New Investigation and Forensic Reports.
Covers all 12 required test scenarios:
1. Field presence on New Investigation screen
2. Valid HTTPS URL accepted
3. Valid HTTP URL accepted
4. Malformed URLs rejected
5. Unsupported schemes (file://, ftp://) rejected
6. Empty URL allows investigation to proceed
7. URL preserved through case creation and analysis
8. URL available after reopening a saved case
9. Generated PDF contains the exact supplied URL
10. HTML and Markdown reports contain the exact supplied URL
11. Missing URL produces correct explanatory message
12. Evidence integrity and audit trail preserved
"""

import base64
import io
import queue
import re
import shutil
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import MagicMock, patch
from PIL import Image

import digitalshield.gui
from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.gui.workers import AnalysisWorker
from digitalshield.gui.screens.new_case import NewCaseScreen
from digitalshield.provenance.client import SafePublicClient
from digitalshield.provenance.service import ProvenanceService
from digitalshield.reporting.service import ReportingService
from digitalshield.reporting.renderers.markdown_renderer import MarkdownRenderer
from digitalshield.reporting.renderers.html_renderer import HTMLRenderer
from digitalshield.reporting.renderers.pdf_renderer import PDFRenderer
from digitalshield.storage.json_store import JSONStore


def _get_tk_root():
    import tkinter as tk
    root = getattr(_get_tk_root, "_root", None)
    if root is not None:
        try:
            if root.winfo_exists():
                return root
        except Exception:
            pass
    try:
        r = tk.Tk()
        r.withdraw()
        _get_tk_root._root = r
        return r
    except Exception:
        _get_tk_root._root = None
        return None


_TK_AVAILABLE = (_get_tk_root() is not None)
_tk_skip = unittest.skipUnless(_TK_AVAILABLE, "Tk display not available in this environment")


def _extract_pdf_text_from_streams(pdf_bytes: bytes) -> str:
    """Decompress Adobe ASCII85/Flate streams from ReportLab PDF to inspect text."""
    decompressed = []
    # Find all stream ... endstream blocks
    pos = 0
    while True:
        s_idx = pdf_bytes.find(b"stream\n", pos)
        if s_idx == -1:
            break
        s_idx += len(b"stream\n")
        e_idx = pdf_bytes.find(b"endstream", s_idx)
        if e_idx == -1:
            break
        raw_stream = pdf_bytes[s_idx:e_idx].strip()
        pos = e_idx + len(b"endstream")

        try:
            a85 = base64.a85decode(raw_stream, adobe=True)
            dec = zlib.decompress(a85)
            decompressed.append(dec.decode("latin1", errors="ignore"))
        except Exception:
            try:
                dec = zlib.decompress(raw_stream)
                decompressed.append(dec.decode("latin1", errors="ignore"))
            except Exception:
                pass

    return "\n".join(decompressed)


class TestPublicSourceURLFieldAndWorkflow(unittest.TestCase):
    def setUp(self):
        self.root = _get_tk_root()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Create synthetic test image
        self.img_path = self.base_dir / "test_image.png"
        img = Image.new("RGB", (100, 100), color=(70, 130, 180))
        img.save(self.img_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 1. The URL field appears on the New Investigation screen
    def test_url_field_appears_on_new_case_screen(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        self.assertTrue(hasattr(screen, "source_url_var"))
        self.assertTrue(hasattr(screen, "source_url_entry"))
        self.assertEqual(screen.source_url_var.get(), "")

    # 2. A valid HTTPS URL is accepted
    def test_valid_https_url_accepted(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)
        screen.case_name_var.set("Test HTTPS Case")
        screen.source_url_var.set("https://example.com/suspected-leak/item123")

        with patch("tkinter.messagebox.showerror") as mock_err:
            screen._start_analysis()
            mock_err.assert_not_called()

        app.start_investigation.assert_called_once()
        kwargs = app.start_investigation.call_args[1]
        self.assertEqual(kwargs.get("source_url"), "https://example.com/suspected-leak/item123")

    # 3. An HTTP URL is handled according to existing safety policy
    def test_valid_http_url_accepted(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)
        screen.case_name_var.set("Test HTTP Case")
        screen.source_url_var.set("http://example.com/image.jpg")

        with patch("tkinter.messagebox.showerror") as mock_err:
            screen._start_analysis()
            mock_err.assert_not_called()

        app.start_investigation.assert_called_once()
        kwargs = app.start_investigation.call_args[1]
        self.assertEqual(kwargs.get("source_url"), "http://example.com/image.jpg")

    # 4. Malformed URLs are rejected appropriately
    def test_malformed_url_rejected(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)
        screen.source_url_var.set("not_a_valid_url")

        with patch("tkinter.messagebox.showerror") as mock_err:
            screen._start_analysis()
            mock_err.assert_called_once()
            err_title, err_msg = mock_err.call_args[0]
            self.assertIn("Invalid Public Source URL", err_title)

        app.start_investigation.assert_not_called()

    # 5. Unsupported schemes such as file:// and ftp:// are rejected
    def test_unsupported_schemes_rejected(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)

        for bad_url in ["file:///C:/Windows/System32/calc.exe", "ftp://example.com/photo.png"]:
            screen.source_url_var.set(bad_url)
            with patch("tkinter.messagebox.showerror") as mock_err:
                screen._start_analysis()
                mock_err.assert_called_once()
                err_title, err_msg = mock_err.call_args[0]
                self.assertIn("Invalid Public Source URL", err_title)
                self.assertIn("permitted", err_msg.lower())

            app.start_investigation.assert_not_called()

    # 5b. Localhost and private IPs rejected
    def test_private_and_loopback_url_rejected(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)

        for bad_url in ["http://localhost:8080/admin", "http://127.0.0.1/leak.png", "http://192.168.1.1/img.png"]:
            screen.source_url_var.set(bad_url)
            with patch("tkinter.messagebox.showerror") as mock_err:
                screen._start_analysis()
                mock_err.assert_called_once()

            app.start_investigation.assert_not_called()

    # 6. An empty URL does not prevent an investigation from starting
    def test_empty_url_allows_investigation_to_proceed(self):
        if self.root is None:
            self.skipTest("Tk display not available")
        app = MagicMock()
        app.base_dir = self.base_dir

        screen = NewCaseScreen(self.root, app)
        screen.selected_path = str(self.img_path)
        screen.source_url_var.set("")

        with patch("tkinter.messagebox.showerror") as mock_err:
            screen._start_analysis()
            mock_err.assert_not_called()

        app.start_investigation.assert_called_once()
        kwargs = app.start_investigation.call_args[1]
        self.assertIsNone(kwargs.get("source_url"))

    # 7. The investigator-provided URL is preserved through case creation and analysis
    def test_url_preserved_through_case_creation_and_analysis(self):
        test_url = "https://example.com/leaked-image-view"
        msg_queue = queue.Queue()

        worker = AnalysisWorker(
            case_name="Preservation Test Case",
            investigator="Officer Smith",
            description="Testing URL retention",
            image_path=self.img_path,
            msg_queue=msg_queue,
            base_dir=self.base_dir,
            source_url=test_url,
        )

        worker.run()

        messages = []
        while not msg_queue.empty():
            messages.append(msg_queue.get_nowait())

        complete_msgs = [m for m in messages if m.get("type") == "complete"]
        self.assertEqual(len(complete_msgs), 1)

        payload = complete_msgs[0]["data"]
        case = payload["case"]
        evidence = payload["evidence"]

        # Case model retains URL
        self.assertEqual(case.source_url, test_url)
        # Evidence model retains URL
        self.assertEqual(evidence.source_url, test_url)
        # Payload retains URL
        self.assertEqual(payload["source_url"], test_url)

        # JSONStore checks
        store = JSONStore(self.base_dir)
        stored_case = store.get_case(case.case_id)
        self.assertIsNotNone(stored_case)
        self.assertEqual(stored_case.get("source_url"), test_url)

        stored_ev = store.get_evidence(evidence.evidence_id)
        self.assertIsNotNone(stored_ev)
        self.assertEqual(stored_ev.get("source_url"), test_url)

        # Provenance record was created without network call
        prov_records = store.list_provenance_by_case(case.case_id)
        self.assertEqual(len(prov_records), 1)
        self.assertEqual(prov_records[0]["source_url"], test_url)
        self.assertEqual(prov_records[0]["source_status"], "Not independently verified")

    # 8. The URL remains available after reopening a saved case
    def test_url_available_after_reopening_case(self):
        test_url = "https://example.com/forum/thread/999"
        case_mgr = CaseManager(self.base_dir)
        ev_mgr = EvidenceManager(self.base_dir)

        case = case_mgr.create_case(
            name="Reopen Test Case",
            investigator="Analyst Jones",
            source_url=test_url,
        )
        ev = ev_mgr.import_evidence(self.img_path, case.case_id, source_url=test_url)

        prov_service = ProvenanceService(self.base_dir)
        prov_service.record_provenance(
            evidence_id=ev.evidence_id,
            source_url=test_url,
            notes="Intake URL",
            fetch_online=False,
        )

        # Simulate reopening from a fresh service / JSONStore instance
        fresh_case_mgr = CaseManager(self.base_dir)
        reopened_case = fresh_case_mgr.get_case(case.case_id)
        self.assertIsNotNone(reopened_case)
        self.assertEqual(reopened_case.source_url, test_url)

        fresh_ev_mgr = EvidenceManager(self.base_dir)
        reopened_ev = fresh_ev_mgr.get_evidence(ev.evidence_id)
        self.assertIsNotNone(reopened_ev)
        self.assertEqual(reopened_ev.source_url, test_url)

        fresh_store = JSONStore(self.base_dir)
        prov_list = fresh_store.list_provenance_by_case(case.case_id)
        self.assertTrue(any(p.get("source_url") == test_url for p in prov_list))


class TestReportURLIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.case_mgr = CaseManager(self.base_dir)
        self.ev_mgr = EvidenceManager(self.base_dir)
        self.reporting_service = ReportingService(self.base_dir)

        # Create test image
        self.img_path = self.base_dir / "report_test_img.png"
        img = Image.new("RGB", (64, 64), color=(120, 80, 40))
        img.save(self.img_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    # 9. The generated PDF contains the exact supplied URL
    def test_pdf_contains_exact_supplied_url(self):
        test_url = "https://example.com/observed-leak-target-777.html"
        case = self.case_mgr.create_case(
            name="PDF URL Case",
            investigator="Examiner Taylor",
            source_url=test_url,
        )
        self.ev_mgr.import_evidence(self.img_path, case.case_id, source_url=test_url)

        rec, file_map = self.reporting_service.generate_report(case.case_id, formats=["pdf"])
        pdf_path = Path(file_map["pdf"])
        self.assertTrue(pdf_path.exists())

        # Inspect decompressed stream contents of PDF for the URL string
        with open(pdf_path, "rb") as f:
            pdf_bytes = f.read()

        decompressed_text = _extract_pdf_text_from_streams(pdf_bytes)
        self.assertIn("observed-leak-target-777.html", decompressed_text)
        self.assertIn("Reported Public Source URL", decompressed_text)

    # 10. HTML and Markdown reports include the URL if those formats are supported
    def test_html_and_markdown_reports_include_exact_url(self):
        test_url = "https://example.com/public-post/item-42"
        case = self.case_mgr.create_case(
            name="MD HTML URL Case",
            investigator="Examiner White",
            source_url=test_url,
        )
        ev = self.ev_mgr.import_evidence(self.img_path, case.case_id, source_url=test_url)

        report_data = self.reporting_service.compile_report_data(case.case_id)
        self.assertEqual(report_data.reported_source_url, test_url)

        # 1. Markdown
        md = MarkdownRenderer.render(report_data)
        self.assertIn("Reported Public Source URL", md)
        self.assertIn(test_url, md)
        self.assertIn("Source information: URL supplied by the investigator.", md)
        self.assertIn("Verification status: Not independently verified.", md)
        self.assertIn(case.case_id, md)
        self.assertIn(ev.evidence_id, md)

        # 2. HTML
        html_out = HTMLRenderer.render(report_data)
        self.assertIn("Reported Public Source URL", html_out)
        self.assertIn(test_url, html_out)
        self.assertIn("URL supplied by the investigator.", html_out)
        self.assertIn("Not independently verified.", html_out)

    # 11. A missing URL produces the correct explanatory message
    def test_missing_url_produces_correct_explanatory_message(self):
        case = self.case_mgr.create_case(
            name="No URL Case",
            investigator="Examiner Black",
            source_url=None,
        )
        self.ev_mgr.import_evidence(self.img_path, case.case_id, source_url=None)

        report_data = self.reporting_service.compile_report_data(case.case_id)
        self.assertIsNone(report_data.reported_source_url)

        # Markdown
        md = MarkdownRenderer.render(report_data)
        self.assertIn("Reported Public Source URL", md)
        self.assertIn("No public source URL was provided by the investigator.", md)

        # HTML
        html_out = HTMLRenderer.render(report_data)
        self.assertIn("Reported Public Source URL", html_out)
        self.assertIn("No public source URL was provided by the investigator.", html_out)

        # PDF
        pdf_buf = io.BytesIO()
        PDFRenderer.render(report_data, pdf_buf)
        pdf_bytes = pdf_buf.getvalue()
        decompressed_pdf = _extract_pdf_text_from_streams(pdf_bytes)
        self.assertIn("No public source URL was provided by the investigator.", decompressed_pdf)

    # 12. Evidence integrity and audit trail preserved
    def test_evidence_integrity_and_audit_trail(self):
        test_url = "https://example.com/source-evidence-page"
        case = self.case_mgr.create_case(
            name="Integrity URL Case",
            investigator="Examiner Green",
            source_url=test_url,
        )
        ev = self.ev_mgr.import_evidence(self.img_path, case.case_id, source_url=test_url)

        # SHA-256 baseline
        orig_sha256 = ev.sha256
        vault_file = Path(ev.stored_path)

        # Generate report
        self.reporting_service.generate_report(case.case_id, formats=["markdown", "html", "pdf"])

        # Check evidence unmodified
        current_sha256 = EvidenceManager.calculate_sha256(vault_file)
        self.assertEqual(orig_sha256, current_sha256)

        # Check audit log
        audit_file = self.base_dir / "audit.log"
        self.assertTrue(audit_file.exists())
        events = self.reporting_service.audit_logger.get_events_by_case(case.case_id)
        actions = [e.get("action") for e in events]

        self.assertIn("CASE_CREATED", actions)
        self.assertIn("EVIDENCE_IMPORTED", actions)
        self.assertIn("SHA256_GENERATED", actions)
        self.assertIn("REPORT_GENERATED", actions)


if __name__ == "__main__":
    unittest.main()
