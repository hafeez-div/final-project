"""
Unit tests for AuditLogger cryptographic logging.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from digitalshield.security.audit import AuditLogger


class TestAuditLogger(unittest.TestCase):
    def setUp(self):
        self.test_dir = Path(tempfile.mkdtemp())
        self.log_file = self.test_dir / "audit.log"
        self.logger = AuditLogger(log_path=self.log_file)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_log_event_chaining(self):
        entry1 = self.logger.log_event("ACTION_1", {"key": "val1"}, actor="Alice")
        entry2 = self.logger.log_event("ACTION_2", {"key": "val2"}, actor="Bob")

        self.assertEqual(entry1["previous_hash"], "0" * 64)
        self.assertEqual(entry2["previous_hash"], entry1["entry_hash"])

        with open(self.log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["entry_hash"], entry1["entry_hash"])
        self.assertEqual(lines[1]["entry_hash"], entry2["entry_hash"])


if __name__ == "__main__":
    unittest.main()
