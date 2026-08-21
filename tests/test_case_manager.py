"""
Unit tests for CaseManager and Case data models.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from digitalshield.case_manager.manager import CaseManager


class TestCaseManager(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.manager = CaseManager(base_dir=self.test_dir)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_create_case_success(self):
        case = self.manager.create_case(
            name="Test Cyber Investigation",
            investigator="Analyst Alice",
            description="Investigating evidence items"
        )
        self.assertTrue(case.case_id.startswith("DS-"))
        self.assertEqual(case.name, "Test Cyber Investigation")
        self.assertEqual(case.investigator, "Analyst Alice")
        self.assertEqual(case.status, "OPEN")

        vault_path = Path(case.vault_path)
        self.assertTrue(vault_path.exists())
        self.assertTrue((vault_path / "evidence").exists())
        self.assertTrue((vault_path / "reports").exists())

    def test_create_case_duplicate_id_raises(self):
        self.manager.create_case(name="Case One", custom_case_id="DS-2026-000001")
        with self.assertRaises(ValueError):
            self.manager.create_case(name="Case Two", custom_case_id="DS-2026-000001")

    def test_list_cases(self):
        self.manager.create_case(name="Case A")
        self.manager.create_case(name="Case B")
        cases = self.manager.list_cases()
        self.assertEqual(len(cases), 2)
        names = [c.name for c in cases]
        self.assertIn("Case A", names)
        self.assertIn("Case B", names)


if __name__ == "__main__":
    unittest.main()
