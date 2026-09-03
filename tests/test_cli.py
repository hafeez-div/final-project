import os
import shutil
import tempfile
import unittest
from pathlib import Path
from click.testing import CliRunner
from digitalshield.cli.main import cli


class TestCLIMain(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.runner = CliRunner(env={"DIGITALSHIELD_DATA_DIR": str(self.test_dir)})
        self.sample_txt = self.test_dir / "sample.txt"
        self.sample_txt.write_text("Test evidence content for CLI test", encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cli_version(self):
        result = self.runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("DigitalShield", result.output)

    def test_cli_case_create(self):
        result = self.runner.invoke(cli, [
            "case", "create",
            "--name", "Test Investigation Case",
            "--investigator", "Dr. Forensics",
            "--description", "Automated test case"
        ])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("Case created successfully", result.output)
        self.assertIn("DS-", result.output)

    def test_cli_case_list(self):
        self.runner.invoke(cli, ["case", "create", "--name", "ListedCase"])
        result = self.runner.invoke(cli, ["case", "list"])
        self.assertEqual(result.exit_code, 0)
        self.assertIn("ListedCase", result.output)

    def test_cli_evidence_import_list_show(self):
        # 1. Create case
        self.runner.invoke(cli, ["case", "create", "--name", "Evidence CLI Case"])

        # 2. Import evidence
        import_res = self.runner.invoke(cli, [
            "evidence", "import",
            str(self.sample_txt),
            "--case", "DS-2026-000001"
        ])
        self.assertEqual(import_res.exit_code, 0)
        self.assertIn("Evidence imported and preserved successfully", import_res.output)
        self.assertIn("EVD-2026-000001", import_res.output)

        # 3. List evidence
        list_res = self.runner.invoke(cli, [
            "evidence", "list",
            "--case", "DS-2026-000001"
        ])
        self.assertEqual(list_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", list_res.output)
        self.assertIn("sample.txt", list_res.output)

        # 4. Show evidence
        show_res = self.runner.invoke(cli, [
            "evidence", "show",
            "EVD-2026-000001"
        ])
        self.assertEqual(show_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", show_res.output)
        self.assertIn("sample.txt", show_res.output)

    def test_cli_evidence_fingerprint_and_compare(self):
        from PIL import Image

        # Create two sample synthetic image files
        img1_path = self.test_dir / "img1.png"
        img2_path = self.test_dir / "img2.png"
        Image.new("RGB", (64, 64), color=(255, 0, 0)).save(img1_path)
        Image.new("RGB", (64, 64), color=(0, 255, 0)).save(img2_path)

        # 1. Create case
        self.runner.invoke(cli, ["case", "create", "--name", "Image Case"])

        # 2. Ingest evidence
        self.runner.invoke(cli, ["evidence", "import", str(img1_path), "--case", "DS-2026-000001"])
        self.runner.invoke(cli, ["evidence", "import", str(img2_path), "--case", "DS-2026-000001"])

        # 3. Test fingerprint command
        fp_res = self.runner.invoke(cli, ["evidence", "fingerprint", "EVD-2026-000001"])
        self.assertEqual(fp_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", fp_res.output)
        self.assertIn("aHash", fp_res.output)
        self.assertIn("dHash", fp_res.output)
        self.assertIn("pHash", fp_res.output)

        # 4. Test compare command
        cmp_res = self.runner.invoke(cli, ["evidence", "compare", "EVD-2026-000001", "EVD-2026-000002"])
        self.assertEqual(cmp_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", cmp_res.output)
        self.assertIn("EVD-2026-000002", cmp_res.output)
        self.assertIn("Overall Similarity", cmp_res.output)
        self.assertIn("Assessment", cmp_res.output)

    def test_cli_analyze_ela(self):
        from PIL import Image

        img_path = self.test_dir / "ela_test.jpg"
        Image.new("RGB", (100, 100), color=(100, 150, 200)).save(img_path, "JPEG", quality=90)

        # 1. Create case
        self.runner.invoke(cli, ["case", "create", "--name", "ELA CLI Case"])

        # 2. Ingest evidence
        self.runner.invoke(cli, ["evidence", "import", str(img_path), "--case", "DS-2026-000001"])

        # 3. Test analyze ela command
        ela_res = self.runner.invoke(cli, ["analyze", "ela", "EVD-2026-000001"])
        self.assertEqual(ela_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", ela_res.output)
        self.assertIn("Error Level Analysis", ela_res.output)
        self.assertIn("Mean ELA Level", ela_res.output)
        self.assertIn("Indicator Score", ela_res.output)
        self.assertIn("Assessment", ela_res.output)
        self.assertIn("Limitations", ela_res.output)

    def test_cli_analyze_deepfake(self):
        from PIL import Image

        img_path = self.test_dir / "deepfake_cli_test.png"
        Image.new("RGB", (512, 512), color=(220, 230, 240)).save(img_path, "PNG")

        # 1. Create case
        self.runner.invoke(cli, ["case", "create", "--name", "Deepfake CLI Case"])

        # 2. Ingest evidence
        self.runner.invoke(cli, ["evidence", "import", str(img_path), "--case", "DS-2026-000001"])

        # 3. Test analyze deepfake command
        df_res = self.runner.invoke(cli, ["analyze", "deepfake", "EVD-2026-000001"])
        self.assertEqual(df_res.exit_code, 0)
        self.assertIn("EVD-2026-000001", df_res.output)
        self.assertIn("AI Deepfake Assessment", df_res.output)
        self.assertIn("Heuristic Baseline", df_res.output)
        self.assertIn("Synthetic Probability", df_res.output)
        self.assertIn("Confidence", df_res.output)
        self.assertIn("Assessment", df_res.output)
        self.assertIn("Indicators", df_res.output)
        self.assertIn("Limitations", df_res.output)

    def test_cli_report_generate_list_show(self):
        # 1. Create case
        self.runner.invoke(cli, ["case", "create", "--name", "Report CLI Case", "--investigator", "Agent Smith"])

        # 2. Import evidence
        self.runner.invoke(cli, ["evidence", "import", str(self.sample_txt), "--case", "DS-2026-000001"])

        # 3. Generate report (markdown)
        gen_res = self.runner.invoke(cli, ["report", "generate", "DS-2026-000001", "--format", "markdown"])
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

        # 4. List reports
        list_res = self.runner.invoke(cli, ["report", "list", "--case", "DS-2026-000001"])
        self.assertEqual(list_res.exit_code, 0)
        self.assertIn(report_id, list_res.output)

        # 5. Show report
        show_res = self.runner.invoke(cli, ["report", "show", report_id])
        self.assertEqual(show_res.exit_code, 0)
        self.assertIn(report_id, show_res.output)
        self.assertIn("DS-2026-000001", show_res.output)


if __name__ == "__main__":
    unittest.main()




