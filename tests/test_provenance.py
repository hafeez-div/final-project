"""
Unit and integration tests for DigitalShield Public URL Provenance Analysis (Phase 7).

All network requests are mocked using unittest.mock. Real external network calls are NEVER made.
All test media files are synthetically generated in-memory.
"""

import io
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path
from PIL import Image, ImageDraw
from click.testing import CliRunner

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.provenance.client import SafePublicClient
from digitalshield.provenance.models import ProvenanceRecord
from digitalshield.provenance.service import ProvenanceService
from digitalshield.storage.json_store import JSONStore
from digitalshield.cli.main import cli


class TestProvenanceAnalysis(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(self.test_dir)
        self.evidence_manager = EvidenceManager(self.test_dir)
        self.client = SafePublicClient()
        self.service = ProvenanceService(self.test_dir, client=self.client)
        self.store = JSONStore(self.test_dir)

        # Create a test case
        self.case = self.case_manager.create_case(
            name="Provenance Forensic Case",
            investigator="Forensics Officer",
            description="Testing Public URL Provenance subsystem"
        )
        self.case_id = self.case.case_id

        # Synthetic image paths
        self.img_path = self.test_dir / "sample_evidence.png"
        self._generate_synthetic_image()

        # Ingest evidence
        self.ev = self.evidence_manager.import_evidence(self.img_path, self.case_id)
        self.evidence_id = self.ev.evidence_id

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _generate_synthetic_image(self):
        """Create a synthetic PNG image."""
        img = Image.new("RGB", (200, 200), color=(150, 180, 210))
        draw = ImageDraw.Draw(img)
        draw.rectangle([30, 30, 170, 170], fill=(255, 100, 100))
        img.save(self.img_path, "PNG")

    # 1. Valid public HTTPS URL validation
    def test_valid_https_url_validation(self):
        res = SafePublicClient.validate_url("https://example.com/page.html")
        self.assertEqual(res, "https://example.com/page.html")

    # 2. HTTP URL validation
    def test_valid_http_url_validation(self):
        res = SafePublicClient.validate_url("http://example.com/photo.jpg")
        self.assertEqual(res, "http://example.com/photo.jpg")

    # 3. Invalid URL rejection
    def test_invalid_url_rejection(self):
        with self.assertRaises(ValueError):
            SafePublicClient.validate_url("not_a_url")
        with self.assertRaises(ValueError):
            SafePublicClient.validate_url("")

    # 4. Unsupported scheme rejection
    def test_unsupported_scheme_rejection(self):
        with self.assertRaises(ValueError) as ctx1:
            SafePublicClient.validate_url("file:///etc/passwd")
        self.assertIn("Only http:// and https:// are permitted", str(ctx1.exception))

        with self.assertRaises(ValueError) as ctx2:
            SafePublicClient.validate_url("ftp://example.com/file.txt")
        self.assertIn("Only http:// and https:// are permitted", str(ctx2.exception))

    # 5. localhost rejection
    def test_localhost_rejection(self):
        with self.assertRaises(ValueError) as ctx:
            SafePublicClient.validate_url("http://localhost:8080/admin")
        self.assertIn("Access denied", str(ctx.exception))

    # 6. Private IP rejection
    def test_private_ip_rejection(self):
        private_urls = [
            "http://127.0.0.1/secret",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/config",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/",
            "http://[::1]/local",
        ]
        for url in private_urls:
            with self.assertRaises(ValueError) as ctx:
                SafePublicClient.validate_url(url)
            self.assertIn("Access denied", str(ctx.exception))

    # 7. URL timeout handling
    @patch("urllib.request.build_opener")
    def test_url_timeout_handling(self, mock_opener):
        mock_instance = MagicMock()
        mock_instance.open.side_effect = TimeoutError("Connection timed out")
        mock_opener.return_value = mock_instance

        client = SafePublicClient(timeout=1)
        with self.assertRaises(ValueError) as ctx:
            client.fetch_public_url("https://example.com/slow")
        self.assertIn("Failed to fetch public URL", str(ctx.exception))

    # 8. Oversized response handling
    @patch("urllib.request.build_opener")
    def test_oversized_response_handling(self, mock_opener):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {"content-type": "text/html"}
        # Return content larger than max_bytes (e.g. 100 bytes limit)
        mock_response.read.return_value = b"X" * 200

        mock_instance = MagicMock()
        mock_instance.open.return_value.__enter__.return_value = mock_response
        mock_opener.return_value = mock_instance

        client = SafePublicClient(max_bytes=100)
        with self.assertRaises(ValueError) as ctx:
            client.fetch_public_url("https://example.com/large")
        self.assertIn("Content exceeds safe limit", str(ctx.exception))

    # 9. Provenance record creation
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_provenance_record_creation(self, mock_fetch):
        mock_fetch.return_value = (
            200,
            {"content-type": "text/html"},
            b"<html><head><title>Test Public Source</title></head><body>Sample</body></html>"
        )

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/post/123",
            observed_account_name="public_user_42"
        )

        self.assertIsInstance(rec, ProvenanceRecord)
        self.assertEqual(rec.evidence_id, self.evidence_id)
        self.assertEqual(rec.case_id, self.case_id)
        self.assertEqual(rec.source_url, "https://example.com/post/123")
        self.assertEqual(rec.source_domain, "example.com")
        self.assertEqual(rec.source_title, "Test Public Source")
        self.assertEqual(rec.observed_account_name, "public_user_42")
        self.assertEqual(rec.source_status, "ACCESSIBLE")
        self.assertTrue(rec.provenance_id.startswith("PRV-"))

    # 10. Provenance persistence
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_provenance_persistence(self, mock_fetch):
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html><title>Page</title></html>")

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/article"
        )

        # Central store check
        stored = self.store.get_provenance(rec.provenance_id)
        self.assertIsNotNone(stored)
        self.assertEqual(stored["provenance_id"], rec.provenance_id)

        # Case analysis folder check
        case_file = self.test_dir / "cases" / self.case_id / "analysis" / f"provenance_{rec.provenance_id}.json"
        self.assertTrue(case_file.exists())

        # Retrieve via service
        retrieved = self.service.get_provenance(rec.provenance_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.source_url, rec.source_url)

    # 11. Evidence ID validation
    def test_invalid_evidence_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.service.record_provenance("EVD-NONEXISTENT-999", "https://example.com")
        self.assertIn("does not exist", str(ctx.exception))

    # 12. Public media fingerprinting & 13. Similarity comparison using EXISTING FingerprintService
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_public_media_fingerprinting_and_similarity(self, mock_fetch):
        # Create identical image in BytesIO buffer
        buf = io.BytesIO()
        with Image.open(self.img_path) as img:
            img.save(buf, format="PNG")
        media_bytes = buf.getvalue()

        # Mock HTML page fetch and media fetch
        def side_effect(url):
            if "media.png" in url:
                return (200, {"content-type": "image/png"}, media_bytes)
            return (200, {"content-type": "text/html"}, b"<html><title>Image Post</title></html>")

        mock_fetch.side_effect = side_effect

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/post/99",
            media_url="https://example.com/media.png"
        )

        self.assertIsNotNone(rec.similarity_score)
        self.assertGreaterEqual(rec.similarity_score, 0.95)
        self.assertEqual(rec.matching_method, "pHash + aHash + dHash")
        self.assertIn("High visual similarity", rec.assessment)

    # 14. Original evidence remains unchanged
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_original_evidence_unmodified(self, mock_fetch):
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html></html>")

        stored_path = Path(self.ev.stored_path)
        mtime_before = stored_path.stat().st_mtime
        sha256_before = self.ev.sha256

        self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/page"
        )

        mtime_after = stored_path.stat().st_mtime
        sha256_after = EvidenceManager.calculate_sha256(stored_path)

        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(sha256_before, sha256_after)

    # 15. Audit logging
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_audit_logging(self, mock_fetch):
        buf = io.BytesIO()
        with Image.open(self.img_path) as img:
            img.save(buf, format="PNG")
        media_bytes = buf.getvalue()

        mock_fetch.return_value = (200, {"content-type": "image/png"}, media_bytes)

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/image.png"
        )

        audit_log = self.test_dir / "audit.log"
        self.assertTrue(audit_log.exists())
        log_text = audit_log.read_text(encoding="utf-8")
        self.assertIn("PROVENANCE_SOURCE_RECORDED", log_text)
        self.assertIn("PROVENANCE_MEDIA_MATCHED", log_text)
        self.assertIn(rec.provenance_id, log_text)

    # 16. Provenance timeline generation
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_provenance_timeline_generation(self, mock_fetch):
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html></html>")

        self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/source1",
            source_timestamp="2026-08-27T08:00:00Z"
        )

        timeline_data = self.service.get_provenance_timeline(self.evidence_id)
        self.assertEqual(timeline_data["evidence_id"], self.evidence_id)
        self.assertGreaterEqual(len(timeline_data["timeline"]), 3)  # Import + Discovered + Visible TS
        event_types = [e["event_type"] for e in timeline_data["timeline"]]
        self.assertIn("EVIDENCE_IMPORTED", event_types)
        self.assertIn("PUBLIC_SOURCE_DISCOVERED", event_types)
        self.assertIn("VISIBLE_SOURCE_TIMESTAMP", event_types)

    # 17. CLI provenance add, 18. CLI provenance list, 19. CLI provenance show
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_cli_provenance_commands(self, mock_fetch):
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html><title>CLI Title</title></html>")

        runner = CliRunner(env={"DIGITALSHIELD_DATA_DIR": str(self.test_dir)})

        # 1. Add provenance
        add_res = runner.invoke(cli, [
            "provenance", "add",
            self.evidence_id,
            "https://example.com/cli_test",
            "--account", "cli_user",
            "--notes", "CLI test note"
        ])
        self.assertEqual(add_res.exit_code, 0)
        self.assertIn("Provenance Record", add_res.output)
        self.assertIn("PRV-", add_res.output)
        self.assertIn("example.com", add_res.output)

        # Extract provenance ID from output
        prov_id = None
        for line in add_res.output.splitlines():
            if "PRV-" in line:
                prov_id = [part for part in line.split() if part.startswith("PRV-")][0]
                break
        self.assertIsNotNone(prov_id)

        # 2. List provenance
        list_res = runner.invoke(cli, ["provenance", "list", "--case", self.case_id])
        self.assertEqual(list_res.exit_code, 0)
        self.assertIn(prov_id, list_res.output)
        self.assertIn("example.com", list_res.output)

        # 3. Show provenance
        show_res = runner.invoke(cli, ["provenance", "show", prov_id])
        self.assertEqual(show_res.exit_code, 0)
        self.assertIn(prov_id, show_res.output)
        self.assertIn("cli_user", show_res.output)

        # 4. Timeline CLI
        tl_res = runner.invoke(cli, ["provenance", "timeline", self.evidence_id])
        self.assertEqual(tl_res.exit_code, 0)
        self.assertIn("EVIDENCE_IMPORTED", tl_res.output)
        self.assertIn("PUBLIC_SOURCE_DISCOVERED", tl_res.output)

    # 20. Unavailable metadata is represented as unknown/null
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_unavailable_metadata_as_unknown(self, mock_fetch):
        # Empty body, no title
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"")

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/no_meta"
        )

        self.assertIsNone(rec.source_title)
        self.assertIsNone(rec.observed_account_name)
        self.assertIsNone(rec.media_url)
        self.assertIsNone(rec.similarity_score)
        self.assertIsNone(rec.matching_method)
        self.assertIsNone(rec.source_timestamp)

    # 21. Neutral attribution phrasing
    @patch.object(SafePublicClient, "fetch_public_url")
    def test_neutral_attribution_phrasing(self, mock_fetch):
        mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html></html>")

        rec = self.service.record_provenance(
            evidence_id=self.evidence_id,
            source_url="https://example.com/neutral_check"
        )

        # Verify assessment does not contain accusatory attribution language
        lower_assessment = rec.assessment.lower()
        self.assertNotIn("is guilty", lower_assessment)
        self.assertNotIn("is a criminal", lower_assessment)
        self.assertNotIn("uploaded the illegal image", lower_assessment)
        self.assertNotIn("is responsible for the crime", lower_assessment)
        self.assertNotIn("created the image", lower_assessment)
        # limitations are allowed to reference "criminal responsibility" as a cautionary disclaimer
        for lim in rec.limitations:
            # Ensure limitation text is advisory (mentions "responsibility") not accusatory
            lim_lower = lim.lower()
            self.assertNotIn("is guilty", lim_lower)
            self.assertNotIn("is a criminal", lim_lower)

    # 22. Safe redirects: validate that a redirect to a private IP is blocked
    def test_safe_redirects_and_no_private_access(self):
        import urllib.error
        import email.message

        # Build a real urllib.error.HTTPError that carries a Location header
        hdrs = email.message.Message()
        hdrs["Location"] = "http://127.0.0.1/admin"

        http_err = urllib.error.HTTPError(
            url="https://example.com/redirect",
            code=302,
            msg="Found",
            hdrs=hdrs,
            fp=None,
        )

        client = SafePublicClient()
        with patch("urllib.request.build_opener") as mock_opener:
            mock_instance = MagicMock()
            mock_instance.open.side_effect = http_err
            mock_opener.return_value = mock_instance

            with self.assertRaises(ValueError) as ctx:
                client.fetch_public_url("https://example.com/redirect")
            self.assertIn("Access denied", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
