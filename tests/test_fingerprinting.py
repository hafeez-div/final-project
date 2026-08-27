"""
Unit and integration tests for DigitalShield Perceptual Fingerprinting Subsystem (Phase 4).

All test images are synthetically generated in-memory. Real victim data is never used.
"""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image, ImageDraw

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.models import (
    AlgorithmFingerprint,
    ComparisonResult,
    FingerprintResult,
)
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.storage.json_store import JSONStore


class TestFingerprinting(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(self.test_dir)
        self.evidence_manager = EvidenceManager(self.test_dir)
        self.service = FingerprintService(self.test_dir)
        self.store = JSONStore(self.test_dir)

        # Create test cases
        self.case = self.case_manager.create_case(
            name="Fingerprint Test Case 1",
            investigator="Forensic Analyst",
            description="Testing perceptual hashing"
        )
        self.case_id = self.case.case_id

        self.case_2 = self.case_manager.create_case(
            name="Fingerprint Test Case 2",
            investigator="Forensic Analyst 2",
            description="Cross-case comparison"
        )
        self.case_id_2 = self.case_2.case_id

        # Synthetic image paths
        self.img_base = self.test_dir / "base_pattern.png"
        self.img_identical = self.test_dir / "identical_copy.png"
        self.img_resized = self.test_dir / "resized_pattern.png"
        self.img_slightly_modified = self.test_dir / "modified_pattern.png"
        self.img_distinct = self.test_dir / "distinct_image.png"
        self.txt_evidence = self.test_dir / "notes.txt"

        # Generate synthetic images
        self._generate_synthetic_test_images()

        # Import base evidence
        self.ev_base = self.evidence_manager.import_evidence(self.img_base, self.case_id)
        self.ev_identical = self.evidence_manager.import_evidence(self.img_identical, self.case_id_2)
        self.ev_resized = self.evidence_manager.import_evidence(self.img_resized, self.case_id)
        self.ev_modified = self.evidence_manager.import_evidence(self.img_slightly_modified, self.case_id)
        self.ev_distinct = self.evidence_manager.import_evidence(self.img_distinct, self.case_id)
        self.ev_txt = self.evidence_manager.import_evidence(self.txt_evidence, self.case_id)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _generate_synthetic_test_images(self):
        """Create synthetic test images with known visual properties."""
        # 1. Base image: 200x200 with geometric shapes
        img = Image.new("RGB", (200, 200), color=(255, 255, 255))
        draw = ImageDraw.Draw(img)
        draw.rectangle([20, 20, 80, 80], fill=(255, 0, 0))
        draw.ellipse([100, 100, 180, 180], fill=(0, 0, 255))
        img.save(self.img_base)

        # 2. Identical copy
        img.save(self.img_identical)

        # 3. Resized version (e.g. 100x100 instead of 200x200)
        img_resized = img.resize((100, 100))
        img_resized.save(self.img_resized)

        # 4. Slightly modified image (added tiny dot)
        img_mod = img.copy()
        draw_mod = ImageDraw.Draw(img_mod)
        draw_mod.point([1, 1], fill=(0, 255, 0))
        img_mod.save(self.img_slightly_modified)

        # 5. Distinct image: black background with yellow cross
        img_dist = Image.new("RGB", (200, 200), color=(0, 0, 0))
        draw_dist = ImageDraw.Draw(img_dist)
        draw_dist.line([0, 0, 200, 200], fill=(255, 255, 0), width=10)
        draw_dist.line([0, 200, 200, 0], fill=(255, 255, 0), width=10)
        img_dist.save(self.img_distinct)

        # 6. Plain text file
        self.txt_evidence.write_text("Case investigation notes", encoding="utf-8")

    def test_generate_fingerprints_success(self):
        """Test extraction of aHash, dHash, and pHash from valid image evidence."""
        fp = self.service.generate_fingerprints(self.ev_base.evidence_id)

        self.assertIsInstance(fp, FingerprintResult)
        self.assertEqual(fp.evidence_id, self.ev_base.evidence_id)
        self.assertEqual(fp.case_id, self.case_id)
        self.assertEqual(len(fp.ahash), 16)  # 64-bit hex is 16 chars
        self.assertEqual(len(fp.dhash), 16)
        self.assertEqual(len(fp.phash), 16)
        self.assertIn("aHash", fp.algorithms)
        self.assertIn("dHash", fp.algorithms)
        self.assertIn("pHash", fp.algorithms)
        self.assertIn("probabilistic", fp.disclaimer.lower())

    def test_fingerprint_persistence(self):
        """Test that fingerprints are saved into JSONStore and reused on subsequent calls."""
        fp1 = self.service.generate_fingerprints(self.ev_base.evidence_id)
        stored = self.store.get_fingerprints(self.ev_base.evidence_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["ahash"], fp1.ahash)

        # Retrieve via service
        fp2 = self.service.get_fingerprints(self.ev_base.evidence_id)
        self.assertIsNotNone(fp2)
        self.assertEqual(fp1.ahash, fp2.ahash)
        self.assertEqual(fp1.generation_timestamp, fp2.generation_timestamp)

    def test_identical_images_comparison(self):
        """Test comparing identical images yields distance 0 and similarity 1.0."""
        res = self.service.compare_fingerprints(self.ev_base.evidence_id, self.ev_identical.evidence_id)

        self.assertIsInstance(res, ComparisonResult)
        self.assertEqual(res.metrics["aHash"].hamming_distance, 0)
        self.assertEqual(res.metrics["dHash"].hamming_distance, 0)
        self.assertEqual(res.metrics["pHash"].hamming_distance, 0)
        self.assertEqual(res.metrics["aHash"].normalized_similarity, 1.0)
        self.assertEqual(res.overall_similarity, 1.0)
        self.assertIn("Identical", res.assessment)

    def test_resized_images_comparison(self):
        """Test comparing resized image produces very high perceptual similarity."""
        res = self.service.compare_fingerprints(self.ev_base.evidence_id, self.ev_resized.evidence_id)

        # Resized images should have nearly identical perceptual hashes
        self.assertGreaterEqual(res.overall_similarity, 0.90)
        self.assertLessEqual(res.metrics["pHash"].hamming_distance, 4)

    def test_slightly_modified_images_comparison(self):
        """Test comparing slightly modified image yields high similarity."""
        res = self.service.compare_fingerprints(self.ev_base.evidence_id, self.ev_modified.evidence_id)

        self.assertGreaterEqual(res.overall_similarity, 0.90)
        self.assertLessEqual(res.metrics["ahash" if "ahash" in res.metrics else "aHash"].hamming_distance, 2)

    def test_clearly_distinct_images_comparison(self):
        """Test comparing completely different images produces low similarity."""
        res = self.service.compare_fingerprints(self.ev_base.evidence_id, self.ev_distinct.evidence_id)

        self.assertLess(res.overall_similarity, 0.70)
        self.assertIn("Low", res.assessment)

    def test_invalid_evidence_id_raises(self):
        """Test querying nonexistent evidence ID raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.generate_fingerprints("EVD-NONEXISTENT-999")
        self.assertIn("does not exist", str(ctx.exception))

    def test_unsupported_evidence_type_raises(self):
        """Test fingerprinting a non-image file raises ValueError."""
        with self.assertRaises(ValueError) as ctx:
            self.service.generate_fingerprints(self.ev_txt.evidence_id)
        self.assertIn("Unsupported evidence type", str(ctx.exception))

    def test_original_evidence_unmodified_after_fingerprinting(self):
        """Forensic rule: Original vault evidence files must remain untouched."""
        stored_path = Path(self.ev_base.stored_path)
        mtime_before = stored_path.stat().st_mtime
        sha256_before = self.ev_base.sha256

        self.service.generate_fingerprints(self.ev_base.evidence_id)

        mtime_after = stored_path.stat().st_mtime
        sha256_after = EvidenceManager.calculate_sha256(stored_path)

        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(sha256_before, sha256_after)

    def test_audit_logs_recorded(self):
        """Test that fingerprint generation and comparison create chained audit log entries."""
        self.service.generate_fingerprints(self.ev_base.evidence_id)
        self.service.compare_fingerprints(self.ev_base.evidence_id, self.ev_distinct.evidence_id)

        audit_log = self.test_dir / "audit.log"
        self.assertTrue(audit_log.exists())
        log_content = audit_log.read_text(encoding="utf-8")
        self.assertIn("FINGERPRINTS_GENERATED", log_content)
        self.assertIn("FINGERPRINTS_COMPARED", log_content)


if __name__ == "__main__":
    unittest.main()
