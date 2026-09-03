"""
Automated unit and integration test suite for DigitalShield Desktop GUI (Phase 9).
"""

import hashlib
import queue
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from PIL import Image

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager, SUPPORTED_EXTENSIONS
from digitalshield.gui.workers import AnalysisWorker, ReportWorker
from digitalshield.gui.theme import Colors, Fonts
from digitalshield.storage.json_store import JSONStore


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
        # Setup existing case with evidence
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
            # Try initializing Tk app in test environment
            app = DigitalShieldApp(base_dir=self.base_dir)
            self.assertIn("home", app.screens)
            self.assertIn("new_case", app.screens)
            self.assertIn("progress", app.screens)
            self.assertIn("results", app.screens)
            self.assertIn("details", app.screens)
            self.assertIn("reports", app.screens)
            self.assertIn("open_case", app.screens)
            app.destroy()
        except Exception as e:
            # If headless environment cannot initialize Tk display, assert gracefully
            self.assertIn("display", str(e).lower() or "tkinter")


# ---------------------------------------------------------------------------
# Helper: detect whether a Tk display is available in this environment
# ---------------------------------------------------------------------------
def _tk_available():
    try:
        import tkinter as tk
        root = tk.Tk()
        root.destroy()
        return True
    except Exception:
        return False


_TK_AVAILABLE = _tk_available()
_tk_skip = unittest.skipUnless(_TK_AVAILABLE, "Tk display not available in this environment")


@_tk_skip
class TestResultsScreenDataBinding(unittest.TestCase):
    """
    Regression tests for ResultsScreen.load_data() after ELAResult bug fix.
    Ensures the screen uses the actual backend field 'anomaly_score' (not the
    non-existent 'indicator_score') and handles None/missing data gracefully.
    """

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
        """Assemble data dict as passed by AnalysisWorker 'complete' message."""
        return {
            "case": None,
            "evidence": ev,
            "metadata": None,
            "fingerprints": None,
            "ela": ela,
            "deepfake": df,
        }

    def _make_results_screen(self):
        """Instantiate ResultsScreen headlessly via a mock app."""
        import tkinter as tk
        from digitalshield.gui.screens.results import ResultsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        screen = ResultsScreen(root, app)
        return root, screen

    def test_results_screen_with_actual_ela_model(self):
        """
        REGRESSION: ResultsScreen.load_data must not raise AttributeError
        when given a real ELAResult object (anomaly_score, not indicator_score).
        """
        root, screen = self._make_results_screen()
        try:
            ela = self._make_ela()
            df = self._make_deepfake()
            data = self._make_gui_data(ela=ela, df=df)
            screen.load_data(data)  # Must not raise

            label_text = screen.ela_score_lbl.cget("text")
            self.assertIn("0.2431", label_text, f"Expected anomaly_score in label, got: {label_text!r}")
            self.assertIn("85", label_text, f"Expected confidence in label, got: {label_text!r}")
            self.assertNotIn("Not available", label_text)
        finally:
            root.destroy()

    def test_results_screen_with_none_ela(self):
        """
        ResultsScreen must display fallback text gracefully when ela is None.
        """
        root, screen = self._make_results_screen()
        try:
            data = self._make_gui_data(ela=None, df=None)
            screen.load_data(data)  # Must not raise

            self.assertIn("Not available", screen.ela_score_lbl.cget("text"))
            self.assertIn("Not available", screen.df_score_lbl.cget("text"))
            self.assertIn("No Error Level Analysis", screen.ela_desc_lbl.cget("text"))
            self.assertIn("No synthetic media assessment", screen.df_desc_lbl.cget("text"))
        finally:
            root.destroy()

    def test_results_screen_with_empty_data_dict(self):
        """
        ResultsScreen.load_data({}) must not raise and must display fallback text.
        """
        root, screen = self._make_results_screen()
        try:
            screen.load_data({})  # Must not raise
            self.assertIn("Not available", screen.ela_score_lbl.cget("text"))
        finally:
            root.destroy()

    def test_results_screen_with_dict_ela(self):
        """
        ResultsScreen must work when ELA data is a plain dict (from JSONStore).
        """
        root, screen = self._make_results_screen()
        try:
            ela_dict = {
                "anomaly_score": 0.5512,
                "confidence": 0.90,
                "assessment": "Moderate anomaly detected.",
            }
            data = self._make_gui_data(ela=ela_dict)
            screen.load_data(data)  # Must not raise

            label_text = screen.ela_score_lbl.cget("text")
            self.assertIn("0.5512", label_text)
        finally:
            root.destroy()

    def test_details_screen_with_actual_ela_model(self):
        """
        REGRESSION: DetailsScreen ELA tab must render 'anomaly_score' and 'disclaimer'
        fields correctly (not crash on 'indicator_score' / 'limitations').
        """
        import tkinter as tk
        from digitalshield.gui.screens.details import DetailsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        app.base_dir = None
        try:
            screen = DetailsScreen(root, app)
            ela = self._make_ela()
            data = {"case": None, "evidence": None, "metadata": None,
                    "fingerprints": None, "ela": ela, "deepfake": None}
            screen.load_data(data)  # Must not raise

            t4 = screen.ela_tab.text_widget
            t4.config(state="normal")
            content = t4.get("1.0", "end")
            t4.config(state="disabled")

            self.assertIn("0.2431", content, "ELA anomaly_score should render in tab")
            self.assertIn("85.0", content, "ELA confidence % should render in tab")
            self.assertIn("Low anomaly detected", content, "ELA assessment should render")
            self.assertIn("investigative indicator", content, "disclaimer should render")
        finally:
            root.destroy()

    def test_details_screen_with_none_ela(self):
        """
        DetailsScreen ELA tab must show 'No ELA record available.' when ela is None.
        """
        import tkinter as tk
        from digitalshield.gui.screens.details import DetailsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        app.base_dir = None
        try:
            screen = DetailsScreen(root, app)
            screen.load_data({"ela": None})  # Must not raise

            t4 = screen.ela_tab.text_widget
            t4.config(state="normal")
            content = t4.get("1.0", "end")
            t4.config(state="disabled")

            self.assertIn("No ELA record available", content)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()

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
            detector_type=DetectorType.HEURISTIC,
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
        """Assemble data dict as passed by AnalysisWorker 'complete' message."""
        return {
            "case": None,
            "evidence": ev,
            "metadata": None,
            "fingerprints": None,
            "ela": ela,
            "deepfake": df,
        }

    def _make_results_screen(self):
        """Instantiate ResultsScreen headlessly via a mock app."""
        import tkinter as tk
        from digitalshield.gui.screens.results import ResultsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        screen = ResultsScreen(root, app)
        return root, screen

    def test_results_screen_with_actual_ela_model(self):
        """
        REGRESSION: ResultsScreen.load_data must not raise AttributeError
        when given a real ELAResult object (anomaly_score, not indicator_score).
        """
        root, screen = self._make_results_screen()
        try:
            ela = self._make_ela()
            df = self._make_deepfake()
            data = self._make_gui_data(ela=ela, df=df)
            screen.load_data(data)  # Must not raise

            label_text = screen.ela_score_lbl.cget("text")
            self.assertIn("0.2431", label_text, f"Expected anomaly_score in label, got: {label_text!r}")
            self.assertIn("85", label_text, f"Expected confidence in label, got: {label_text!r}")
            self.assertNotIn("Not available", label_text)
        finally:
            root.destroy()

    def test_results_screen_with_none_ela(self):
        """
        ResultsScreen must display fallback text gracefully when ela is None.
        """
        root, screen = self._make_results_screen()
        try:
            data = self._make_gui_data(ela=None, df=None)
            screen.load_data(data)  # Must not raise

            self.assertIn("Not available", screen.ela_score_lbl.cget("text"))
            self.assertIn("Not available", screen.df_score_lbl.cget("text"))
            self.assertIn("No Error Level Analysis", screen.ela_desc_lbl.cget("text"))
            self.assertIn("No synthetic media assessment", screen.df_desc_lbl.cget("text"))
        finally:
            root.destroy()

    def test_results_screen_with_empty_data_dict(self):
        """
        ResultsScreen.load_data({}) must not raise and must display fallback text.
        """
        root, screen = self._make_results_screen()
        try:
            screen.load_data({})  # Must not raise
            self.assertIn("Not available", screen.ela_score_lbl.cget("text"))
        finally:
            root.destroy()

    def test_results_screen_with_dict_ela(self):
        """
        ResultsScreen must work when ELA data is a plain dict (from JSONStore).
        """
        root, screen = self._make_results_screen()
        try:
            ela_dict = {
                "anomaly_score": 0.5512,
                "confidence": 0.90,
                "assessment": "Moderate anomaly detected.",
            }
            data = self._make_gui_data(ela=ela_dict)
            screen.load_data(data)  # Must not raise

            label_text = screen.ela_score_lbl.cget("text")
            self.assertIn("0.5512", label_text)
        finally:
            root.destroy()

    def test_details_screen_with_actual_ela_model(self):
        """
        REGRESSION: DetailsScreen ELA tab must render 'anomaly_score' and 'disclaimer'
        fields correctly (not crash on 'indicator_score' / 'limitations').
        """
        import tkinter as tk
        from digitalshield.gui.screens.details import DetailsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        app.base_dir = None
        try:
            screen = DetailsScreen(root, app)
            ela = self._make_ela()
            data = {"case": None, "evidence": None, "metadata": None,
                    "fingerprints": None, "ela": ela, "deepfake": None}
            screen.load_data(data)  # Must not raise

            t4 = screen.ela_tab.text_widget
            t4.config(state="normal")
            content = t4.get("1.0", "end")
            t4.config(state="disabled")

            self.assertIn("0.2431", content, "ELA anomaly_score should render in tab")
            self.assertIn("85.0", content, "ELA confidence % should render in tab")
            self.assertIn("Low anomaly detected", content, "ELA assessment should render")
            self.assertIn("investigative indicator", content, "disclaimer should render")
        finally:
            root.destroy()

    def test_details_screen_with_none_ela(self):
        """
        DetailsScreen ELA tab must show 'No ELA record available.' when ela is None.
        """
        import tkinter as tk
        from digitalshield.gui.screens.details import DetailsScreen
        root = tk.Tk()
        root.withdraw()
        app = MagicMock()
        app.base_dir = None
        try:
            screen = DetailsScreen(root, app)
            screen.load_data({"ela": None})  # Must not raise

            t4 = screen.ela_tab.text_widget
            t4.config(state="normal")
            content = t4.get("1.0", "end")
            t4.config(state="disabled")

            self.assertIn("No ELA record available", content)
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
