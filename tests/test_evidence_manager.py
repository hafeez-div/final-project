"""
Unit tests for EvidenceManager, Evidence data model, and vault preservation.
"""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager


class TestEvidenceManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(base_dir=self.test_dir)
        self.evidence_manager = EvidenceManager(base_dir=self.test_dir)

        # Create a test case
        self.case = self.case_manager.create_case(name="Evidence Unit Test Case")

        # Create synthetic test files
        self.sample_txt = self.test_dir / "synthetic_sample.txt"
        self.sample_txt.write_text("DigitalShield Synthetic Forensic Evidence File Sample", encoding="utf-8")

        self.sample_png = self.test_dir / "synthetic_image.png"
        # Synthetic PNG header bytes
        self.sample_png.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 50)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_import_evidence_success(self):
        evidence = self.evidence_manager.import_evidence(self.sample_txt, self.case.case_id)

        self.assertTrue(evidence.evidence_id.startswith("EVD-"))
        self.assertEqual(evidence.case_id, self.case.case_id)
        self.assertEqual(evidence.original_filename, "synthetic_sample.txt")
        self.assertEqual(evidence.mime_type, "text/plain")

        # Check preserved vault file exists
        preserved_path = Path(evidence.stored_path)
        self.assertTrue(preserved_path.exists())

        # Verify preserved file content matches
        self.assertEqual(preserved_path.read_text(encoding="utf-8"), "DigitalShield Synthetic Forensic Evidence File Sample")

        # Check SHA-256
        expected_sha = hashlib.sha256(b"DigitalShield Synthetic Forensic Evidence File Sample").hexdigest()
        self.assertEqual(evidence.sha256, expected_sha)

        # Check case evidence count updated
        updated_case = self.case_manager.get_case(self.case.case_id)
        self.assertEqual(updated_case.evidence_count, 1)

        # Check vault manifest.json created
        manifest_path = Path(self.case.vault_path) / "evidence" / "evidence_manifest.json"
        self.assertTrue(manifest_path.exists())

        with open(manifest_path, "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(len(manifest), 1)
        self.assertEqual(manifest[0]["evidence_id"], evidence.evidence_id)
        self.assertEqual(manifest[0]["sha256"], expected_sha)

    def test_original_file_unmodified(self):
        original_mtime = self.sample_txt.stat().st_mtime
        original_content = self.sample_txt.read_bytes()

        self.evidence_manager.import_evidence(self.sample_txt, self.case.case_id)

        self.assertEqual(self.sample_txt.read_bytes(), original_content)
        self.assertEqual(self.sample_txt.stat().st_mtime, original_mtime)

    def test_chunked_sha256_large_file(self):
        large_file = self.test_dir / "large_synthetic_sample.txt"
        # Generate 150 KB of synthetic data (> 64 KB chunk size)
        data = b"ABCDEF1234567890" * 10000
        large_file.write_bytes(data)

        computed_sha = EvidenceManager.calculate_sha256(large_file)
        expected_sha = hashlib.sha256(data).hexdigest()
        self.assertEqual(computed_sha, expected_sha)

    def test_import_nonexistent_file_raises(self):
        missing_path = self.test_dir / "nonexistent.txt"
        with self.assertRaises(FileNotFoundError):
            self.evidence_manager.import_evidence(missing_path, self.case.case_id)

    def test_import_unsupported_file_raises(self):
        unsupported_file = self.test_dir / "test_script.py"
        unsupported_file.write_text("print('test')", encoding="utf-8")
        with self.assertRaises(ValueError) as ctx:
            self.evidence_manager.import_evidence(unsupported_file, self.case.case_id)
        self.assertIn("Unsupported file format", str(ctx.exception))

    def test_import_nonexistent_case_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.evidence_manager.import_evidence(self.sample_txt, "DS-2026-999999")
        self.assertIn("does not exist", str(ctx.exception))

    def test_import_duplicate_evidence_raises(self):
        self.evidence_manager.import_evidence(self.sample_txt, self.case.case_id)
        with self.assertRaises(ValueError) as ctx:
            self.evidence_manager.import_evidence(self.sample_txt, self.case.case_id)
        self.assertIn("Duplicate evidence import", str(ctx.exception))

    def test_list_and_get_evidence(self):
        ev1 = self.evidence_manager.import_evidence(self.sample_txt, self.case.case_id)
        ev2 = self.evidence_manager.import_evidence(self.sample_png, self.case.case_id)

        items = self.evidence_manager.list_evidence(self.case.case_id)
        self.assertEqual(len(items), 2)
        eids = [e.evidence_id for e in items]
        self.assertIn(ev1.evidence_id, eids)
        self.assertIn(ev2.evidence_id, eids)

        retrieved = self.evidence_manager.get_evidence(ev1.evidence_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.original_filename, "synthetic_sample.txt")


    def test_filename_preservation_and_no_duplicate_extensions(self):
        """
        Regression Test (Issue 1): Verify exact original filenames are preserved
        without duplicate extensions or silent mutations.
        """
        from PIL import Image

        filenames_to_test = [
            "photo.jpg",
            "image.jpeg",
            "evidence.png",
            "dcx.jpg.jpg",  # user's exact double extension case
        ]

        for fname in filenames_to_test:
            case = self.case_manager.create_case(name=f"Case for {fname}")
            src_file = self.test_dir / fname
            
            # Create a real small image
            img = Image.new("RGB", (64, 64), color=(100, 150, 200))
            if fname.endswith(".png"):
                img.save(src_file, "PNG")
            else:
                img.save(src_file, "JPEG")

            with open(src_file, "rb") as f:
                sha_orig = hashlib.sha256(f.read()).hexdigest()

            ev = self.evidence_manager.import_evidence(src_file, case.case_id)

            # 1. Exact original filename preserved
            self.assertEqual(ev.original_filename, fname)
            
            # 2. Stored filename has evidence_id prefix + exact filename (no extra extensions)
            self.assertEqual(ev.stored_filename, f"{ev.evidence_id}_{fname}")

            # 3. Preserved file exists in vault
            self.assertTrue(Path(ev.stored_path).exists())

            # 4. Original file is 100% untouched
            with open(src_file, "rb") as f:
                sha_after = hashlib.sha256(f.read()).hexdigest()
            self.assertEqual(sha_orig, sha_after)

    def test_content_based_mime_detection(self):
        """
        Regression Test (Issue 2): Verify MIME detection inspects content magic bytes,
        properly distinguishing JPEG vs PNG even if extension is mislabeled.
        """
        from PIL import Image

        # True JPEG
        jpeg_path = self.test_dir / "genuine.jpg"
        Image.new("RGB", (32, 32), color=(255, 0, 0)).save(jpeg_path, "JPEG")
        self.assertEqual(self.evidence_manager.infer_mime_type(jpeg_path), "image/jpeg")

        # True PNG
        png_path = self.test_dir / "genuine.png"
        Image.new("RGB", (32, 32), color=(0, 255, 0)).save(png_path, "PNG")
        self.assertEqual(self.evidence_manager.infer_mime_type(png_path), "image/png")

        # PNG content saved with .jpg extension (like user's test image)
        mislabeled_path = self.test_dir / "mislabeled.jpg"
        Image.new("RGB", (32, 32), color=(0, 0, 255)).save(mislabeled_path, "PNG")
        self.assertEqual(self.evidence_manager.infer_mime_type(mislabeled_path), "image/png")


if __name__ == "__main__":
    unittest.main()
