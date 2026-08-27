"""
Unit and integration tests for DigitalShield AI Deepfake & Synthetic Media Assessment (Phase 6).

All test media files are synthetically generated in-memory. Real victim data is never used.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image, ImageDraw

from digitalshield.case_manager.manager import CaseManager
from digitalshield.detection.deepfake import BaselineDeepfakeDetector, DeepfakeAssessmentService
from digitalshield.detection.interfaces import BaseDeepfakeDetector
from digitalshield.detection.models import DeepfakeAnalysisResult, DetectorType
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.storage.json_store import JSONStore


class MockCustomDetector(BaseDeepfakeDetector):
    """Mock detector for testing detector interface pluggability."""
    @property
    def name(self) -> str:
        return "Mock Custom Neural Detector"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.TRAINED_MODEL

    def analyze(self, evidence_path, evidence_metadata, derived_features=None):
        return DeepfakeAnalysisResult(
            evidence_id=evidence_metadata.get("evidence_id", "MOCK"),
            case_id=evidence_metadata.get("case_id", "MOCK"),
            original_filename=evidence_metadata.get("original_filename"),
            analysis_timestamp="2026-08-27T12:00:00+00:00",
            detector_name=self.name,
            detector_type=self.detector_type,
            synthetic_probability=0.42,
            confidence=0.88,
            assessment="Mock probabilistic assessment for interface pluggability testing.",
            indicators=["Mock indicator 1", "Mock indicator 2"],
            limitations=["Mock model limitation"],
            features_used=["Mock feature set"],
            status="COMPLETED"
        )


class TestDeepfakeAssessment(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(self.test_dir)
        self.evidence_manager = EvidenceManager(self.test_dir)
        self.service = DeepfakeAssessmentService(self.test_dir)
        self.store = JSONStore(self.test_dir)

        # Create a test case
        self.case = self.case_manager.create_case(
            name="Deepfake Synthetic Media Case",
            investigator="Forensics Officer",
            description="Testing AI deepfake assessment module"
        )
        self.case_id = self.case.case_id

        # Synthetic image paths
        self.img_gen_res = self.test_dir / "gen_square_512.jpg"
        self.img_standard_png = self.test_dir / "standard_graphic.png"
        self.txt_evidence = self.test_dir / "document.txt"

        self._generate_synthetic_test_media()

        # Ingest evidence
        self.ev_gen = self.evidence_manager.import_evidence(self.img_gen_res, self.case_id)
        self.ev_png = self.evidence_manager.import_evidence(self.img_standard_png, self.case_id)
        self.ev_txt = self.evidence_manager.import_evidence(self.txt_evidence, self.case_id)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _generate_synthetic_test_media(self):
        """Create synthetic test images in memory."""
        # 1. 512x512 synthetic image (common generative resolution)
        img1 = Image.new("RGB", (512, 512), color=(200, 210, 220))
        draw1 = ImageDraw.Draw(img1)
        for i in range(0, 512, 32):
            draw1.line([(0, i), (512, i)], fill=(i % 255, 100, 200))
        img1.save(self.img_gen_res, "JPEG", quality=90)

        # 2. Non-square PNG image (300x200)
        img2 = Image.new("RGB", (300, 200), color=(100, 150, 200))
        draw2 = ImageDraw.Draw(img2)
        draw2.rectangle([40, 40, 260, 160], fill=(255, 255, 255))
        img2.save(self.img_standard_png, "PNG")

        # 3. Text file
        self.txt_evidence.write_text("Non-image file content", encoding="utf-8")

    def test_valid_image_analysis(self):
        """1. Test deepfake assessment on a valid image evidence item."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)

        self.assertIsInstance(res, DeepfakeAnalysisResult)
        self.assertEqual(res.evidence_id, self.ev_gen.evidence_id)
        self.assertEqual(res.case_id, self.case_id)
        self.assertEqual(res.original_filename, self.ev_gen.original_filename)
        self.assertEqual(res.status, "COMPLETED")

    def test_result_structure(self):
        """2. Test all required fields exist and are well-formed in DeepfakeAnalysisResult."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)

        self.assertIsNotNone(res.evidence_id)
        self.assertIsNotNone(res.case_id)
        self.assertIsNotNone(res.analysis_timestamp)
        self.assertIsNotNone(res.detector_name)
        self.assertIsNotNone(res.detector_type)
        self.assertIsInstance(res.synthetic_probability, float)
        self.assertIsInstance(res.confidence, float)
        self.assertIsInstance(res.assessment, str)
        self.assertIsInstance(res.indicators, list)
        self.assertGreater(len(res.indicators), 0)
        self.assertIsInstance(res.limitations, list)
        self.assertGreater(len(res.limitations), 0)
        self.assertIsInstance(res.features_used, list)
        self.assertGreater(len(res.features_used), 0)

    def test_probability_range(self):
        """3. Test synthetic probability is strictly bounded in [0.0, 1.0]."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)
        self.assertGreaterEqual(res.synthetic_probability, 0.0)
        self.assertLessEqual(res.synthetic_probability, 1.0)

        res2 = self.service.assess_evidence(self.ev_png.evidence_id)
        self.assertGreaterEqual(res2.synthetic_probability, 0.0)
        self.assertLessEqual(res2.synthetic_probability, 1.0)

    def test_confidence_range(self):
        """4. Test confidence score is strictly bounded in [0.0, 1.0]."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)
        self.assertGreaterEqual(res.confidence, 0.0)
        self.assertLessEqual(res.confidence, 1.0)

    def test_invalid_evidence_id_raises(self):
        """5. Test analyzing nonexistent evidence ID raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.assess_evidence("EVD-NONEXISTENT-999")
        self.assertIn("does not exist", str(ctx.exception))

    def test_unsupported_evidence_type_raises(self):
        """6. Test analyzing non-image evidence raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.assess_evidence(self.ev_txt.evidence_id)
        self.assertIn("Unsupported evidence type", str(ctx.exception))

    def test_analysis_persistence(self):
        """7. Test assessment persistence in central JSONStore and case analysis directory."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)

        # 1. Central store
        stored = self.store.get_deepfake(self.ev_gen.evidence_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["evidence_id"], self.ev_gen.evidence_id)
        self.assertEqual(stored["synthetic_probability"], res.synthetic_probability)

        # 2. Case analysis folder
        case_file = self.test_dir / "cases" / self.case_id / "analysis" / f"deepfake_{self.ev_gen.evidence_id}.json"
        self.assertTrue(case_file.exists())

        # 3. Retrieve via service
        retrieved = self.service.get_assessment(self.ev_gen.evidence_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.synthetic_probability, res.synthetic_probability)

    def test_audit_logging(self):
        """8. Test append-only audit logging of deepfake assessment event."""
        self.service.assess_evidence(self.ev_gen.evidence_id)

        audit_log = self.test_dir / "audit.log"
        self.assertTrue(audit_log.exists())
        log_text = audit_log.read_text(encoding="utf-8")
        self.assertIn("DEEPFAKE_ASSESSMENT_EXECUTED", log_text)
        self.assertIn(self.ev_gen.evidence_id, log_text)

    def test_original_evidence_unchanged(self):
        """9. Forensic integrity: Original vault evidence files must remain untouched."""
        stored_path = Path(self.ev_gen.stored_path)
        mtime_before = stored_path.stat().st_mtime
        sha256_before = self.ev_gen.sha256

        self.service.assess_evidence(self.ev_gen.evidence_id)

        mtime_after = stored_path.stat().st_mtime
        sha256_after = EvidenceManager.calculate_sha256(stored_path)

        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(sha256_before, sha256_after)

    def test_deterministic_baseline_behavior(self):
        """10. Test baseline detector produces deterministic, reproducible results."""
        detector = BaselineDeepfakeDetector()
        meta = {
            "evidence_id": self.ev_gen.evidence_id,
            "case_id": self.case_id,
            "original_filename": self.ev_gen.original_filename,
        }
        res1 = detector.analyze(Path(self.ev_gen.stored_path), meta)
        res2 = detector.analyze(Path(self.ev_gen.stored_path), meta)

        self.assertEqual(res1.synthetic_probability, res2.synthetic_probability)
        self.assertEqual(res1.confidence, res2.confidence)
        self.assertEqual(res1.assessment, res2.assessment)
        self.assertEqual(res1.indicators, res2.indicators)

    def test_correct_detector_type_labeling(self):
        """11. Test baseline detector is accurately identified as 'heuristic baseline'."""
        res = self.service.assess_evidence(self.ev_gen.evidence_id)
        self.assertEqual(res.detector_type, DetectorType.HEURISTIC_BASELINE)
        self.assertEqual(res.detector_type.value, "heuristic baseline")

    def test_custom_detector_pluggability(self):
        """12. Test modular pluggability of custom / future trained models."""
        custom_detector = MockCustomDetector()
        custom_service = DeepfakeAssessmentService(self.test_dir, detector=custom_detector)

        res = custom_service.assess_evidence(self.ev_png.evidence_id, force_recompute=True)
        self.assertEqual(res.detector_name, "Mock Custom Neural Detector")
        self.assertEqual(res.detector_type, DetectorType.TRAINED_MODEL)
        self.assertEqual(res.synthetic_probability, 0.42)
        self.assertEqual(res.confidence, 0.88)


if __name__ == "__main__":
    unittest.main()
