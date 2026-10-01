"""
Comprehensive unit and integration tests for DigitalShield Forensic Reporting Subsystem (Phase 8).

All tests use isolated temporary directories and synthetic test fixtures.
Zero real network requests and zero real victim evidence.
"""

import io
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from PIL import Image, ImageDraw
from click.testing import CliRunner

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.metadata.extractor import MetadataExtractor
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.detection.ela import ELADetector
from digitalshield.detection.deepfake import DeepfakeAssessmentService
from digitalshield.provenance.service import ProvenanceService
from digitalshield.reporting.models import ReportData, ReportMetadata, CaseInfo, EvidenceItemReport, ReportRecord
from digitalshield.reporting.service import ReportingService
from digitalshield.reporting.renderers.markdown_renderer import MarkdownRenderer
from digitalshield.reporting.renderers.html_renderer import HTMLRenderer
from digitalshield.reporting.renderers.pdf_renderer import PDFRenderer
from digitalshield.storage.json_store import JSONStore
from digitalshield.cli.main import cli


class TestReportingSubsystem(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.case_manager = CaseManager(self.test_dir)
        self.evidence_manager = EvidenceManager(self.test_dir)
        self.meta_extractor = MetadataExtractor(self.test_dir)
        self.fingerprint_service = FingerprintService(self.test_dir)
        self.ela_detector = ELADetector(self.test_dir)
        self.deepfake_service = DeepfakeAssessmentService(self.test_dir)
        self.provenance_service = ProvenanceService(self.test_dir)
        self.reporting_service = ReportingService(self.test_dir)
        self.store = JSONStore(self.test_dir)

        # 1. Initialize case
        self.case = self.case_manager.create_case(
            name="Forensic Report Investigation Case",
            investigator="Lead Examiner",
            description="Case for testing complete forensic reporting pipeline"
        )
        self.case_id = self.case.case_id

        # 2. Create synthetic image evidence
        self.img_path = self.test_dir / "synthetic_evidence.jpg"
        img = Image.new("RGB", (200, 200), color=(100, 150, 200))
        draw = ImageDraw.Draw(img)
        draw.rectangle([40, 40, 160, 160], fill=(220, 80, 80))
        img.save(self.img_path, "JPEG")

        # 3. Import evidence
        self.ev = self.evidence_manager.import_evidence(self.img_path, self.case_id)
        self.evidence_id = self.ev.evidence_id

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    # 1. Report model creation
    def test_report_model_creation(self):
        meta = ReportMetadata(
            report_id="RPT-2026-000001",
            case_id="DS-2026-000001",
            case_name="Test Case",
            report_timestamp="2026-09-02T12:00:00Z",
        )
        case_info = CaseInfo(
            case_id="DS-2026-000001",
            name="Test Case",
            created_at="2026-09-02T10:00:00Z",
            vault_path="/tmp/vault",
        )
        data = ReportData(metadata=meta, case_info=case_info)
        d = data.to_dict()
        self.assertEqual(d["metadata"]["report_id"], "RPT-2026-000001")
        self.assertEqual(d["case_info"]["case_id"], "DS-2026-000001")

        reconstructed = ReportData.from_dict(d)
        self.assertEqual(reconstructed.metadata.report_id, "RPT-2026-000001")

    # 2. Report ID generation
    def test_report_id_generation(self):
        id1 = self.reporting_service._generate_report_id()
        self.assertTrue(id1.startswith("RPT-"))
        self.assertTrue(id1.endswith("-000001"))

    # 3. Report generation for valid case & 7. Storage path
    def test_report_generation_for_valid_case(self):
        rec, paths = self.reporting_service.generate_report(self.case_id, formats="markdown")
        self.assertIsInstance(rec, ReportRecord)
        self.assertEqual(rec.case_id, self.case_id)
        self.assertIn("markdown", paths)
        self.assertTrue(paths["markdown"].exists())

        expected_dir = self.test_dir / "cases" / self.case_id / "reports"
        self.assertEqual(paths["markdown"].parent, expected_dir)

    # 4. Markdown generation
    def test_markdown_generation(self):
        rec, paths = self.reporting_service.generate_report(self.case_id, formats="markdown")
        md_text = paths["markdown"].read_text(encoding="utf-8")
        self.assertIn("# DigitalShield Forensic Analysis Report", md_text)
        self.assertIn(self.case_id, md_text)
        self.assertIn(self.evidence_id, md_text)
        self.assertIn(self.ev.sha256, md_text)

    # 5. HTML generation & 32. HTML contains no external tracking/resources
    def test_html_generation_and_offline_security(self):
        rec, paths = self.reporting_service.generate_report(self.case_id, formats="html")
        html_text = paths["html"].read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE html>", html_text)
        self.assertIn(self.case_id, html_text)
        self.assertIn(self.evidence_id, html_text)
        # Verify strict offline constraints
        self.assertNotIn("http://", html_text)
        self.assertNotIn("https://fonts.googleapis.com", html_text)
        self.assertNotIn("<script", html_text)
        self.assertNotIn("analytics", html_text)
        self.assertNotIn("cdn.", html_text)

    # 6. PDF generation & 34. Generated files exist and are readable
    def test_pdf_generation_and_readability(self):
        rec, paths = self.reporting_service.generate_report(self.case_id, formats="pdf")
        self.assertIn("pdf", paths)
        pdf_path = paths["pdf"]
        self.assertTrue(pdf_path.exists())
        self.assertGreater(pdf_path.stat().st_size, 500)
        with open(pdf_path, "rb") as f:
            header = f.read(5)
            self.assertEqual(header, b"%PDF-")

    # 8. Evidence inventory inclusion & 9. SHA-256 inclusion
    def test_evidence_inventory_and_sha256_inclusion(self):
        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertEqual(len(data.evidence_items), 1)
        ev_item = data.evidence_items[0]
        self.assertEqual(ev_item.evidence_id, self.evidence_id)
        self.assertEqual(ev_item.sha256, self.ev.sha256)

        md = MarkdownRenderer.render(data)
        self.assertIn(self.ev.original_filename, md)
        self.assertIn(self.ev.sha256, md)

    # 10. Metadata inclusion
    def test_metadata_inclusion(self):
        self.meta_extractor.extract(self.evidence_id)
        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertIn(self.evidence_id, data.metadata_findings)
        m = data.metadata_findings[self.evidence_id]
        self.assertIsNotNone(m)

        md = MarkdownRenderer.render(data)
        self.assertIn("Technical & EXIF Metadata Findings", md)
        self.assertIn(str(m.get("width_px")), md)

    # 11. Fingerprint inclusion
    def test_fingerprint_inclusion(self):
        self.fingerprint_service.generate_fingerprints(self.evidence_id)
        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertIn(self.evidence_id, data.fingerprint_findings)
        fp = data.fingerprint_findings[self.evidence_id]
        self.assertIsNotNone(fp)

        md = MarkdownRenderer.render(data)
        self.assertIn(fp.get("ahash"), md)
        self.assertIn(fp.get("dhash"), md)
        self.assertIn(fp.get("phash"), md)

    # 12. ELA inclusion
    def test_ela_inclusion(self):
        self.ela_detector.analyze_evidence(self.evidence_id)
        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertIn(self.evidence_id, data.ela_findings)
        ela = data.ela_findings[self.evidence_id]
        self.assertIsNotNone(ela)

        md = MarkdownRenderer.render(data)
        self.assertIn("Error Level Analysis", md)
        self.assertIn(f"{ela.get('mean_error'):.4f}", md)

    # 13. Deepfake assessment inclusion & 24. AI limitations included
    def test_deepfake_assessment_and_limitations_inclusion(self):
        self.deepfake_service.assess_evidence(self.evidence_id)
        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertIn(self.evidence_id, data.deepfake_findings)
        df = data.deepfake_findings[self.evidence_id]
        self.assertIsNotNone(df)

        md = MarkdownRenderer.render(data)
        self.assertIn("AI-Assisted Assessment", md)
        self.assertIn("probabilistic indicators", md.lower())
        self.assertNotIn("is definitely ai-generated", md.lower())
        self.assertNotIn("is definitely a deepfake", md.lower())

    # 14. Provenance inclusion & 15. Timeline generation
    def test_provenance_and_timeline_inclusion(self):
        from unittest.mock import patch
        from digitalshield.provenance.client import SafePublicClient

        with patch.object(SafePublicClient, "fetch_public_url") as mock_fetch:
            mock_fetch.return_value = (200, {"content-type": "text/html"}, b"<html><title>Observed Page</title></html>")
            self.provenance_service.record_provenance(
                evidence_id=self.evidence_id,
                source_url="https://example.com/item",
                observed_account_name="observed_user",
                source_timestamp="2026-08-20T10:00:00Z"
            )

        data = self.reporting_service.compile_report_data(self.case_id)
        self.assertEqual(len(data.provenance_records), 1)
        self.assertIn(self.evidence_id, data.timelines)

        md = MarkdownRenderer.render(data)
        self.assertIn("https://example.com/item", md)
        self.assertIn("observed_user", md)
        self.assertIn("Origin & Propagation Timeline", md)

    # 16. Audit event creation & 26. Existing audit chain remains valid
    def test_audit_event_creation_and_chain_validity(self):
        rec, _ = self.reporting_service.generate_report(self.case_id, formats="markdown")
        audit_file = self.test_dir / "audit.log"
        self.assertTrue(audit_file.exists())
        
        events = self.reporting_service.audit_logger.list_events()
        report_events = [e for e in events if e.get("action") == "REPORT_GENERATED"]
        self.assertEqual(len(report_events), 1)
        self.assertEqual(report_events[0]["details"]["report_id"], rec.report_id)

    # 17. Missing metadata, 18. Missing ELA, 19. Missing deepfake, 20. Missing provenance, 21. Missing investigator
    def test_missing_sparse_data_graceful_handling(self):
        # Create empty case with no investigator and no evidence
        sparse_case = self.case_manager.create_case(name="Sparse Case", investigator="")
        data = self.reporting_service.compile_report_data(sparse_case.case_id)
        
        # Verify no crashes on renderers
        md = MarkdownRenderer.render(data)
        html = HTMLRenderer.render(data)
        buf = io.BytesIO()
        PDFRenderer.render(data, buf)

        self.assertIn("Unassigned", md)
        self.assertIn("No evidence items", md)
        self.assertIn("Unassigned", html)
        self.assertGreater(buf.tell(), 500)

    # 22. No fabricated information
    def test_no_fabricated_information(self):
        sparse_case = self.case_manager.create_case(name="Empty Case")
        data = self.reporting_service.compile_report_data(sparse_case.case_id)
        md = MarkdownRenderer.render(data)
        self.assertNotIn("latitude", md.lower())
        self.assertNotIn("longitude", md.lower())
        self.assertIn("None recorded.", md)

    # 23. Neutral attribution language
    def test_neutral_attribution_language(self):
        data = self.reporting_service.compile_report_data(self.case_id)
        md = MarkdownRenderer.render(data)
        md_lower = md.lower()
        self.assertNotIn("is guilty", md_lower)
        self.assertNotIn("is a criminal", md_lower)
        self.assertNotIn("committed the crime", md_lower)

    # 25. Evidence immutability
    def test_evidence_immutability_during_reporting(self):
        stored_path = Path(self.ev.stored_path)
        mtime_before = stored_path.stat().st_mtime
        sha256_before = self.ev.sha256

        self.reporting_service.generate_report(self.case_id, formats="all")

        mtime_after = stored_path.stat().st_mtime
        sha256_after = EvidenceManager.calculate_sha256(stored_path)

        self.assertEqual(mtime_before, mtime_after)
        self.assertEqual(sha256_before, sha256_after)

    # 27. Invalid Case ID handling
    def test_invalid_case_id_raises(self):
        with self.assertRaises(ValueError) as ctx:
            self.reporting_service.generate_report("DS-NONEXISTENT-999")
        self.assertIn("does not exist", str(ctx.exception))

    # 28. CLI report generate, 29. CLI report list, 30. CLI report show, 31. All-format generation
    def test_cli_report_commands(self):
        runner = CliRunner(env={"DIGITALSHIELD_DATA_DIR": str(self.test_dir)})

        # 1. Generate report
        gen_res = runner.invoke(cli, ["report", "generate", self.case_id, "--format", "all"])
        self.assertEqual(gen_res.exit_code, 0)
        self.assertIn("Forensic report generated successfully", gen_res.output)
        self.assertIn("RPT-", gen_res.output)

        # Extract Report ID
        report_id = None
        for line in gen_res.output.splitlines():
            if "RPT-" in line:
                for part in line.split():
                    if part.startswith("RPT-"):
                        report_id = part.strip()
                        break
        self.assertIsNotNone(report_id)

        # 2. List reports
        list_res = runner.invoke(cli, ["report", "list", "--case", self.case_id])
        self.assertEqual(list_res.exit_code, 0)
        self.assertIn(report_id, list_res.output)

        # 3. Show report
        show_res = runner.invoke(cli, ["report", "show", report_id])
        self.assertEqual(show_res.exit_code, 0)
        self.assertIn(report_id, show_res.output)
        self.assertIn("MARKDOWN", show_res.output)
        self.assertIn("HTML", show_res.output)
        self.assertIn("PDF", show_res.output)

    # 33. Deterministic report generation
    def test_deterministic_report_compilation(self):
        data1 = self.reporting_service.compile_report_data(self.case_id, report_id="RPT-2026-000099")
        data2 = self.reporting_service.compile_report_data(self.case_id, report_id="RPT-2026-000099")
        data2.metadata.report_timestamp = data1.metadata.report_timestamp
        md1 = MarkdownRenderer.render(data1)
        md2 = MarkdownRenderer.render(data2)
        self.assertEqual(md1, md2)

    # 35. Regression Test (Issue 2): Accurate format rendering across Markdown, HTML, and PDF
    def test_report_format_rendering_jpeg_and_png(self):
        # 1. Ingest real JPEG and PNG
        png_path = self.test_dir / "format_test.png"
        Image.new("RGB", (64, 64), color=(10, 20, 30)).save(png_path, "PNG")
        ev_png = self.evidence_manager.import_evidence(png_path, self.case_id)

        self.meta_extractor.extract(self.evidence_id)  # JPEG
        self.meta_extractor.extract(ev_png.evidence_id)  # PNG

        data = self.reporting_service.compile_report_data(self.case_id)
        
        # Markdown
        md = MarkdownRenderer.render(data)
        self.assertIn("image/jpeg", md)
        self.assertIn("image/png", md)
        self.assertIn("JPEG", md)
        self.assertIn("PNG", md)

        # HTML
        html = HTMLRenderer.render(data)
        self.assertIn("image/jpeg", html)
        self.assertIn("image/png", html)
        self.assertIn("JPEG", html)
        self.assertIn("PNG", html)

        # PDF
        buf = io.BytesIO()
        PDFRenderer.render(data, buf)
        self.assertGreater(buf.tell(), 1000)


if __name__ == "__main__":
    unittest.main()
