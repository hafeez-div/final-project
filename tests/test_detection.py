"""
Unit and integration tests for DigitalShield Image Manipulation Detection and ELA (Phase 5).

All test images are synthetically generated in-memory. Real victim data is never used.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image, ImageDraw

from digitalshield.case_manager.manager import CaseManager
from digitalshield.detection.ela import ELADetector
from digitalshield.detection.models import ELAResult, ELAStatistics
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.storage.json_store import JSONStore


class TestELADetection(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(self.test_dir)
        self.evidence_manager = EvidenceManager(self.test_dir)
        self.detector = ELADetector(self.test_dir)
        self.store = JSONStore(self.test_dir)

        # Create a test case
        self.case = self.case_manager.create_case(
            name="ELA Forensics Case",
            investigator="Forensics Officer",
            description="Testing Error Level Analysis module"
        )
        self.case_id = self.case.case_id

        # Synthetic image paths
        self.img_jpeg = self.test_dir / "sample_photo.jpg"
        self.img_png = self.test_dir / "sample_graphics.png"
        self.img_tampered_sim = self.test_dir / "composite_image.jpg"
        self.txt_evidence = self.test_dir / "readme.txt"

        self._generate_synthetic_test_images()

        # Ingest evidence
        self.ev_jpeg = self.evidence_manager.import_evidence(self.img_jpeg, self.case_id)
        self.ev_png = self.evidence_manager.import_evidence(self.img_png, self.case_id)
        self.ev_tampered = self.evidence_manager.import_evidence(self.img_tampered_sim, self.case_id)
        self.ev_txt = self.evidence_manager.import_evidence(self.txt_evidence, self.case_id)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _generate_synthetic_test_images(self):
        """Create synthetic test images with various compression & pattern profiles."""
        # 1. Valid JPEG with smooth pattern
        img_jpg = Image.new("RGB", (200, 200), color=(180, 200, 220))
        draw_jpg = ImageDraw.Draw(img_jpg)
        for i in range(0, 200, 20):
            draw_jpg.line([(0, i), (200, i)], fill=(i, 150, 200))
        img_jpg.save(self.img_jpeg, "JPEG", quality=85)

        # 2. Valid PNG with geometric layout
        img_png = Image.new("RGBA", (150, 150), color=(255, 255, 255, 255))
        draw_png = ImageDraw.Draw(img_png)
        draw_png.rectangle([20, 20, 100, 100], fill=(255, 0, 0, 255))
        draw_png.ellipse([60, 60, 140, 140], fill=(0, 255, 0, 128))
        img_png.save(self.img_png, "PNG")

        # 3. Composite / high-contrast synthetic image
        img_comp = Image.new("RGB", (250, 250), color=(255, 255, 255))
        draw_comp = ImageDraw.Draw(img_comp)
        for y in range(0, 250, 5):
            draw_comp.line([(0, y), (250, y)], fill=(y % 255, (y * 2) % 255, (y * 3) % 255))
        draw_comp.rectangle([50, 50, 180, 180], fill=(0, 0, 0))
        img_comp.save(self.img_tampered_sim, "JPEG", quality=95)

        # 4. Text file
        self.txt_evidence.write_text("Case forensic documentation", encoding="utf-8")

    def test_valid_jpeg_analysis(self):
        """Test ELA execution on a valid JPEG image evidence file."""
        res = self.detector.analyze_evidence(self.ev_jpeg.evidence_id)

        self.assertIsInstance(res, ELAResult)
        self.assertEqual(res.evidence_id, self.ev_jpeg.evidence_id)
        self.assertEqual(res.case_id, self.case_id)
        self.assertEqual(res.image_width, 200)
        self.assertEqual(res.image_height, 200)
        self.assertEqual(res.recompression_quality, 90)
        self.assertGreaterEqual(res.mean_error, 0.0)
        self.assertGreaterEqual(res.max_error, 0.0)
        self.assertIsInstance(res.statistics, ELAStatistics)

    def test_png_input_handling(self):
        """Test that PNG images (including RGBA) are correctly handled and analyzed."""
        res = self.detector.analyze_evidence(self.ev_png.evidence_id)

        self.assertIsInstance(res, ELAResult)
        self.assertEqual(res.evidence_id, self.ev_png.evidence_id)
        self.assertEqual(res.color_mode, "RGB")
        self.assertEqual(res.image_width, 150)
        self.assertEqual(res.image_height, 150)
        self.assertEqual(res.status, "COMPLETED")

    def test_invalid_evidence_id_raises(self):
        """Test analyzing a nonexistent evidence ID raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_evidence("EVD-NONEXISTENT-999")
        self.assertIn("does not exist", str(ctx.exception))

    def test_unsupported_evidence_type_raises(self):
        """Test analyzing a non-image evidence file raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.detector.analyze_evidence(self.ev_txt.evidence_id)
        self.assertIn("Unsupported evidence type", str(ctx.exception))

    def test_analysis_result_structure(self):
        """Test all required fields in the ELAResult structure."""
        res = self.detector.analyze_evidence(self.ev_tampered.evidence_id)

        self.assertIsNotNone(res.evidence_id)
        self.assertIsNotNone(res.case_id)
        self.assertIsNotNone(res.analysis_timestamp)
        self.assertGreater(res.image_width, 0)
        self.assertGreater(res.image_height, 0)
        self.assertGreaterEqual(res.anomaly_score, 0.0)
        self.assertLessEqual(res.anomaly_score, 1.0)
        self.assertGreaterEqual(res.confidence, 0.0)
        self.assertLessEqual(res.confidence, 1.0)
        self.assertIn("probabilistic", res.disclaimer.lower())
        self.assertIn("probabilistic", res.assessment.lower())

    def test_original_evidence_unmodified(self):
        """Forensic rule: Original vault evidence files must remain untouched."""
        stored_path = Path(self.ev_jpeg.stored_path)
        mtime_before = stored_path.stat().st_mtime
        sha256_before = self.ev_jpeg.sha256

        self.detector.analyze_evidence(self.ev_jpeg.evidence_id)

        mtime_after = stored_path.stat().st_mtime
        sha256_after = EvidenceManager.calculate_sha256(stored_path)

        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(sha256_before, sha256_after)

    def test_ela_statistics_generated(self):
        """Test detailed ELA statistics generation (mean, max, stddev, rms, high error pixels)."""
        res = self.detector.analyze_evidence(self.ev_tampered.evidence_id)
        stats = res.statistics

        self.assertIsInstance(stats.mean_error, float)
        self.assertIsInstance(stats.max_error, float)
        self.assertIsInstance(stats.stddev_error, float)
        self.assertIsInstance(stats.rms_error, float)
        self.assertIsInstance(stats.high_error_pixels, int)
        self.assertIsInstance(stats.high_error_ratio, float)
        self.assertGreaterEqual(stats.high_error_ratio, 0.0)
        self.assertLessEqual(stats.high_error_ratio, 1.0)

    def test_analysis_persistence(self):
        """Test that ELA results are stored in JSONStore and case analysis directory."""
        res = self.detector.analyze_evidence(self.ev_jpeg.evidence_id)

        # 1. Check central JSONStore
        stored_dict = self.store.get_ela(self.ev_jpeg.evidence_id)
        self.assertIsNotNone(stored_dict)
        self.assertEqual(stored_dict["evidence_id"], self.ev_jpeg.evidence_id)
        self.assertEqual(stored_dict["anomaly_score"], res.anomaly_score)

        # 2. Check case-specific analysis file
        case_file = self.test_dir / "cases" / self.case_id / "analysis" / f"ela_{self.ev_jpeg.evidence_id}.json"
        self.assertTrue(case_file.exists())

        # 3. Retrieve via detector service
        retrieved = self.detector.get_analysis(self.ev_jpeg.evidence_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.anomaly_score, res.anomaly_score)

    def test_audit_logs_recorded(self):
        """Test that running ELA records an audit log entry."""
        self.detector.analyze_evidence(self.ev_jpeg.evidence_id)

        audit_log = self.test_dir / "audit.log"
        self.assertTrue(audit_log.exists())
        log_content = audit_log.read_text(encoding="utf-8")
        self.assertIn("ELA_ANALYSIS_EXECUTED", log_content)
        self.assertIn(self.ev_jpeg.evidence_id, log_content)


if __name__ == "__main__":
    unittest.main()
