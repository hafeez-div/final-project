"""
Automated unit and integration test suite for DigitalShield Desktop GUI (Phase 9).
"""

import hashlib
import os
import queue
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from PIL import Image

import digitalshield.gui  # Ensures TCL_LIBRARY / TK_LIBRARY setup on Windows
from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager, SUPPORTED_EXTENSIONS
from digitalshield.gui.workers import AnalysisWorker, ReportWorker
from digitalshield.gui.theme import Colors, Fonts
from digitalshield.storage.json_store import JSONStore


def _get_tk_root():
    """Get or create a reusable singleton withdrawn Tk root for headless tests."""
    import tkinter as tk
    if not hasattr(_get_tk_root, "_root") or _get_tk_root._root is None:
        try:
            r = tk.Tk()
            r.withdraw()
            _get_tk_root._root = r
        except Exception:
            _get_tk_root._root = None
    return _get_tk_root._root


_TK_AVAILABLE = (_get_tk_root() is not None)
_tk_skip = unittest.skipUnless(_TK_AVAILABLE, "Tk display not available in this environment")


class TestDesktopGUI(unittest.TestCase):
    """
    Test suite for GUI worker threads, state management, and backend coordination.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        # Create a test image
        self.test_img_path = self.base_dir / "gui_test_evidence.png"
        img = Image.new("RGB", (256, 256), color=(60, 120, 180))
        img.save(self.test_img_path)

        with open(self.test_img_path, "rb") as f:
            self.orig_sha = hashlib.sha256(f.read()).hexdigest()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_gui_imports_and_theme_constants(self):
        """Verify GUI theme definitions and imports."""
        self.assertIsNotNone(Colors.PRIMARY)
        self.assertIsNotNone(Colors.ACCENT)
        self.assertIsNotNone(Colors.SUCCESS)
        self.assertEqual(Fonts.FAMILY, "Segoe UI")

    def test_analysis_worker_full_pipeline(self):
        """Verify AnalysisWorker coordinates all 6 forensic stages without freezing UI."""
        msg_queue = queue.Queue()
        worker = AnalysisWorker(
            case_name="GUI Worker Test Case",
            investigator="Lead Analyst",
            description="Testing background execution",
            image_path=self.test_img_path,
            msg_queue=msg_queue,
            base_dir=self.base_dir,
        )

        # Run synchronously in test
        worker.run()

        # Collect all emitted messages
        messages = []
        while not msg_queue.empty():
            messages.append(msg_queue.get_nowait())

        # Verify step messages
        step_starts = [m for m in messages if m.get("type") == "step_start"]
        step_dones = [m for m in messages if m.get("type") == "step_done"]
        complete_msgs = [m for m in messages if m.get("type") == "complete"]

        self.assertEqual(len(step_starts), 6)
        self.assertEqual(len(step_dones), 6)
        self.assertEqual(len(complete_msgs), 1)

        # Verify payload content
        data = complete_msgs[0].get("data", {})
        self.assertIn("case", data)
        self.assertIn("evidence", data)
        self.assertIn("metadata", data)
        self.assertIn("fingerprints", data)
        self.assertIn("ela", data)
        self.assertIn("deepfake", data)

        case = data["case"]
        ev = data["evidence"]
        self.assertTrue(case.case_id.startswith("DS-"))
        self.assertTrue(ev.evidence_id.startswith("EVD-"))
        self.assertEqual(ev.sha256, self.orig_sha)

        # Verify original file untouched
        with open(self.test_img_path, "rb") as f:
            current_sha = hashlib.sha256(f.read()).hexdigest()
        self.assertEqual(current_sha, self.orig_sha)

    def test_analysis_worker_error_handling(self):
        """Verify AnalysisWorker emits error message on failure."""
        msg_queue = queue.Queue()
        invalid_path = self.base_dir / "nonexistent_image.png"

        worker = AnalysisWorker(
            case_name="Error Case",
            investigator="Analyst",
            description="Testing error handling",
            image_path=invalid_path,
            msg_queue=msg_queue,
            base_dir=self.base_dir,
        )
        worker.run()

        messages = []
        while not msg_queue.empty():
            messages.append(msg_queue.get_nowait())

        error_msgs = [m for m in messages if m.get("type") == "error"]
        self.assertTrue(len(error_msgs) >= 1)
        self.assertTrue(any("does not exist" in m.get("error", "").lower() or "not found" in m.get("error", "").lower() for m in error_msgs))

    def test_report_worker_generation(self):
        """Verify ReportWorker generates multi-format reports via ReportingService."""
        case_mgr = CaseManager(self.base_dir)
        ev_mgr = EvidenceManager(self.base_dir)
        case = case_mgr.create_case("Report Worker Case", "Analyst", "Testing reports")
        ev_mgr.import_evidence(self.test_img_path, case.case_id)

        msg_queue = queue.Queue()
        worker = ReportWorker(
            case_id=case.case_id,
            formats=["markdown", "html", "pdf"],
            msg_queue=msg_queue,
            base_dir=self.base_dir,
        )
        worker.run()

        messages = []
        while not msg_queue.empty():
            messages.append(msg_queue.get_nowait())

        success_msgs = [m for m in messages if m.get("type") == "report_success"]
        self.assertEqual(len(success_msgs), 1)

        record = success_msgs[0].get("record")
        file_map = success_msgs[0].get("file_map", {})

        self.assertTrue(record.report_id.startswith("RPT-"))
        self.assertIn("markdown", file_map)
        self.assertIn("html", file_map)
        self.assertIn("pdf", file_map)

        for fmt, p in file_map.items():
            self.assertTrue(Path(p).exists())
            self.assertGreater(Path(p).stat().st_size, 0)

    def test_evidence_format_compatibility(self):
        """Verify GUI respects EvidenceManager.SUPPORTED_EXTENSIONS."""
        self.assertIn(".jpg", SUPPORTED_EXTENSIONS)
        self.assertIn(".png", SUPPORTED_EXTENSIONS)
        self.assertIn(".webp", SUPPORTED_EXTENSIONS)
        self.assertIn(".gif", SUPPORTED_EXTENSIONS)

    def test_gui_app_initialization_headless_safe(self):
        """Verify DigitalShieldApp initializes frames cleanly."""
        try:
            from digitalshield.gui.app import DigitalShieldApp
            app = DigitalShieldApp(base_dir=self.base_dir)
            self.assertIn("home", app.screens)
            self.assertIn("new_case", app.screens)
            self.assertIn("progress", app.screens)
            self.assertIn("results", app.screens)
            self.assertIn("details", app.screens)
            self.assertIn("provenance", app.screens)
            self.assertIn("reports", app.screens)
            self.assertIn("open_case", app.screens)
            app.destroy()
        except Exception as e:
            self.assertTrue(
                any(k in str(e).lower() for k in ("display", "tcl", "tkinter", "init.tcl", "tk.tcl")),
                f"Unexpected exception during Tk initialization: {e}",
            )


@_tk_skip
class TestResultsScreenDataBinding(unittest.TestCase):
    """
    Regression tests for ResultsScreen.load_data() and DetailsScreen.load_data()
    after ELAResult bug fix.
    Ensures screens use actual backend field 'anomaly_score' (not non-existent 'indicator_score')
    and handle None/missing data defensively.
    """

    def setUp(self):
        self.root = _get_tk_root()

    def _make_ela(self, **overrides):
        """Build a real ELAResult using actual backend model."""
        from digitalshield.detection.models import ELAResult, ELAStatistics
        stats = ELAStatistics(
            mean_error=1.5,
            max_error=12.0,
            stddev_error=2.3,
            rms_error=2.8,
            high_error_pixels=420,
            high_error_ratio=0.0065,
        )
        defaults = dict(
            evidence_id="EVD-TEST-001",
            case_id="DS-TEST-001",
            original_filename="test.jpg",
            analysis_timestamp="2026-01-01T00:00:00",
            image_width=256,
            image_height=256,
            color_mode="RGB",
            recompression_quality=90,
            statistics=stats,
            mean_error=stats.mean_error,
            max_error=stats.max_error,
            anomaly_score=0.2431,
            confidence=0.85,
            assessment="Low anomaly detected. No evidence of tampering.",
            disclaimer="ELA is an investigative indicator only.",
            status="complete",
        )
        defaults.update(overrides)
        return ELAResult(**defaults)

    def _make_deepfake(self, **overrides):
        """Build a real DeepfakeAnalysisResult using actual backend model."""
        from digitalshield.detection.models import DeepfakeAnalysisResult, DetectorType
        defaults = dict(
            evidence_id="EVD-TEST-001",
            case_id="DS-TEST-001",
            analysis_timestamp="2026-01-01T00:00:00",
            detector_name="DigitalShield Heuristic",
            detector_type=DetectorType.HEURISTIC_BASELINE,
            synthetic_probability=0.12,
            confidence=0.78,
            assessment="Image appears authentic.",
            indicators=["No GAN artifacts"],
            features_used=["frequency_analysis"],
            limitations=["Accuracy limited on heavily compressed images."],
        )
        defaults.update(overrides)
        return DeepfakeAnalysisResult(**defaults)

    def _make_gui_data(self, ela=None, df=None, ev=None):
        return {
            "case": None,
            "evidence": ev,
            "metadata": None,
            "fingerprints": None,
            "ela": ela,
            "deepfake": df,
        }

    def test_results_screen_with_actual_ela_model(self):
        from digitalshield.gui.screens.results import ResultsScreen
        app = MagicMock()
        screen = ResultsScreen(self.root, app)
        ela = self._make_ela()
        df = self._make_deepfake()
        data = self._make_gui_data(ela=ela, df=df)
        screen.load_data(data)

        label_text = screen.ela_score_lbl.cget("text")
        self.assertIn("0.2431", label_text)
        self.assertIn("85", label_text)
        self.assertNotIn("Not available", label_text)

    def test_results_screen_with_none_ela(self):
        from digitalshield.gui.screens.results import ResultsScreen
        app = MagicMock()
        screen = ResultsScreen(self.root, app)
        data = self._make_gui_data(ela=None, df=None)
        screen.load_data(data)

        self.assertIn("Not available", screen.ela_score_lbl.cget("text"))
        self.assertIn("Not available", screen.df_score_lbl.cget("text"))
        self.assertIn("No Error Level Analysis", screen.ela_desc_lbl.cget("text"))
        self.assertIn("No synthetic media assessment", screen.df_desc_lbl.cget("text"))

    def test_results_screen_with_empty_data_dict(self):
        from digitalshield.gui.screens.results import ResultsScreen
        app = MagicMock()
        screen = ResultsScreen(self.root, app)
        screen.load_data({})
        self.assertIn("Not available", screen.ela_score_lbl.cget("text"))

    def test_results_screen_with_dict_ela(self):
        from digitalshield.gui.screens.results import ResultsScreen
        app = MagicMock()
        screen = ResultsScreen(self.root, app)
        ela_dict = {
            "anomaly_score": 0.5512,
            "confidence": 0.90,
            "assessment": "Moderate anomaly detected.",
        }
        data = self._make_gui_data(ela=ela_dict)
        screen.load_data(data)

        label_text = screen.ela_score_lbl.cget("text")
        self.assertIn("0.5512", label_text)

    def test_details_screen_with_actual_ela_model(self):
        from digitalshield.gui.screens.details import DetailsScreen
        app = MagicMock()
        app.base_dir = None
        screen = DetailsScreen(self.root, app)
        ela = self._make_ela()
        data = {
            "case": None,
            "evidence": None,
            "metadata": None,
            "fingerprints": None,
            "ela": ela,
            "deepfake": None,
        }
        screen.load_data(data)

        t4 = screen.ela_tab.text_widget
        t4.config(state="normal")
        content = t4.get("1.0", "end")
        t4.config(state="disabled")

        self.assertIn("0.2431", content)
        self.assertIn("85.0", content)
        self.assertIn("Low anomaly detected", content)
        self.assertIn("investigative indicator", content)

    def test_details_screen_with_none_ela(self):
        from digitalshield.gui.screens.details import DetailsScreen
        app = MagicMock()
        app.base_dir = None
        screen = DetailsScreen(self.root, app)
        screen.load_data({"ela": None})

        t4 = screen.ela_tab.text_widget
        t4.config(state="normal")
        content = t4.get("1.0", "end")
        t4.config(state="disabled")

        self.assertIn("No ELA record available", content)

    def test_details_screen_with_provenance_records(self):
        from digitalshield.gui.screens.details import DetailsScreen
        from digitalshield.case_manager.manager import CaseManager
        from digitalshield.evidence.manager import EvidenceManager
        from digitalshield.provenance.service import ProvenanceService

        temp_dir = tempfile.TemporaryDirectory()
        base_dir = Path(temp_dir.name)
        try:
            app = MagicMock()
            app.base_dir = base_dir

            case_mgr = CaseManager(base_dir=base_dir)
            ev_mgr = EvidenceManager(base_dir=base_dir)
            case = case_mgr.create_case(name="Prov GUI Test")
            
            test_img = base_dir / "prov_test.png"
            Image.new("RGB", (64, 64), color=(10, 20, 30)).save(test_img, "PNG")
            ev = ev_mgr.import_evidence(test_img, case.case_id)

            # Record a provenance observation via existing backend
            prov_service = ProvenanceService(base_dir=base_dir)
            with patch.object(prov_service.client, "validate_url", return_value="https://example.com/item/100"):
                with patch.object(prov_service.client, "fetch_public_url", return_value=(200, {"content-type": "text/html"}, b"<html><title>News Post</title></html>")):
                    record = prov_service.record_provenance(
                        evidence_id=ev.evidence_id,
                        source_url="https://example.com/item/100",
                        observed_account_name="@investigative_journal",
                        notes="Observed during routine check",
                    )

            screen = DetailsScreen(self.root, app)
            screen.load_data({"case": case, "evidence": ev})

            t6 = screen.prov_tab.text_widget
            t6.config(state="normal")
            content = t6.get("1.0", "end")
            t6.config(state="disabled")

            self.assertIn("example.com", content)
            self.assertIn("@investigative_journal", content)
            self.assertIn("Total Provenance Observations: 1", content)
        finally:
            temp_dir.cleanup()


@_tk_skip
class TestProvenanceScreenInteractive(unittest.TestCase):
    """
    Regression tests for ProvenanceScreen user interaction, safety controls,
    and live data refreshing.
    """

    def setUp(self):
        self.root = _get_tk_root()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)

        self.case_mgr = CaseManager(base_dir=self.base_dir)
        self.ev_mgr = EvidenceManager(base_dir=self.base_dir)
        self.case = self.case_mgr.create_case(name="Interactive Prov Case")

        self.test_img = self.base_dir / "sample.jpg"
        Image.new("RGB", (32, 32), color=(50, 100, 150)).save(self.test_img, "JPEG")
        self.ev = self.ev_mgr.import_evidence(self.test_img, self.case.case_id)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_provenance_screen_ui_components_and_safe_recording(self):
        from digitalshield.gui.screens.provenance import ProvenanceScreen

        app = MagicMock()
        app.base_dir = self.base_dir
        app.case_data = {"case": self.case, "evidence": self.ev}

        screen = ProvenanceScreen(self.root, app)
        screen.load_data(app.case_data)

        self.assertIn(self.ev.original_filename, screen.target_lbl.cget("text"))

        # Fill form
        screen.url_var.set("https://example.com/photo/42")
        screen.account_var.set("@archivist")
        screen.notes_var.set("Archival record lead")

        from digitalshield.provenance.client import SafePublicClient

        with patch.object(SafePublicClient, "validate_url", return_value="https://example.com/photo/42"):
            with patch.object(SafePublicClient, "fetch_public_url", return_value=(200, {"content-type": "text/html"}, b"<html><title>Archive Photo</title></html>")):
                with patch("digitalshield.gui.screens.provenance.messagebox.showinfo"):
                    screen._record_provenance()

        screen_text = screen.records_text.get("1.0", "end")
        self.assertIn("example.com", screen_text)
        self.assertIn("@archivist", screen_text)

    def test_provenance_screen_private_url_rejection(self):
        from digitalshield.gui.screens.provenance import ProvenanceScreen

        app = MagicMock()
        app.base_dir = self.base_dir
        app.case_data = {"case": self.case, "evidence": self.ev}

        screen = ProvenanceScreen(self.root, app)
        screen.load_data(app.case_data)

        screen.url_var.set("http://127.0.0.1/private/file.png")

        with patch("digitalshield.gui.screens.provenance.messagebox.showerror") as mock_err:
            screen._record_provenance()
            mock_err.assert_called_once()
            err_title, err_msg = mock_err.call_args[0]
            self.assertIn("Safety Rejection", err_title)
            self.assertIn("safety requirements", err_msg.lower())


class TestMetadataFormatDetection(unittest.TestCase):
    """
    Regression tests for MetadataExtractor detecting JPEG vs PNG from file content.
    """

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.case_mgr = CaseManager(base_dir=self.base_dir)
        self.ev_mgr = EvidenceManager(base_dir=self.base_dir)
        self.case = self.case_mgr.create_case(name="Format Detection Case")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_jpeg_and_png_metadata_detection(self):
        from digitalshield.metadata.extractor import MetadataExtractor

        # 1. Genuine JPEG
        jpeg_file = self.base_dir / "real.jpg"
        Image.new("RGB", (120, 80), color=(200, 100, 50)).save(jpeg_file, "JPEG")
        ev_jpeg = self.ev_mgr.import_evidence(jpeg_file, self.case.case_id)

        extractor = MetadataExtractor(base_dir=self.base_dir)
        meta_jpeg = extractor.extract(ev_jpeg.evidence_id)

        self.assertEqual(meta_jpeg.file_format, "JPEG")
        self.assertEqual(meta_jpeg.mime_type, "image/jpeg")
        self.assertEqual(meta_jpeg.width_px, 120)
        self.assertEqual(meta_jpeg.height_px, 80)

        # 2. Genuine PNG
        png_file = self.base_dir / "real.png"
        Image.new("RGB", (150, 90), color=(50, 100, 200)).save(png_file, "PNG")
        ev_png = self.ev_mgr.import_evidence(png_file, self.case.case_id)

        meta_png = extractor.extract(ev_png.evidence_id)
        self.assertEqual(meta_png.file_format, "PNG")
        self.assertEqual(meta_png.mime_type, "image/png")
        self.assertEqual(meta_png.width_px, 150)
        self.assertEqual(meta_png.height_px, 90)


if __name__ == "__main__":
    unittest.main()
