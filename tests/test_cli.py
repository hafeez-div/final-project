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


if __name__ == "__main__":
    unittest.main()
