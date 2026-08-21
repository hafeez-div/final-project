"""
Local JSON store for persistent case records and evidence metadata storage.
"""

import json
from pathlib import Path
from typing import Dict, List, Optional


class JSONStore:
    """
    Simple, secure file-backed JSON store for managing local DigitalShield entities.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            base_dir = Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.cases_file = self.base_dir / "cases.json"
        self.evidence_file = self.base_dir / "evidence.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if not self.cases_file.exists():
            self._write_file(self.cases_file, {})
        if not self.evidence_file.exists():
            self._write_file(self.evidence_file, {})

    def _read_file(self, target_file: Path) -> Dict[str, dict]:
        if not target_file.exists():
            return {}
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _write_file(self, target_file: Path, data: Dict[str, dict]) -> None:
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    # --- Case Methods ---
    def save_case(self, case_dict: dict) -> None:
        """Save or update a case in the JSON store."""
        data = self._read_file(self.cases_file)
        case_id = case_dict["case_id"]
        data[case_id] = case_dict
        self._write_file(self.cases_file, data)

    def get_case(self, case_id: str) -> Optional[dict]:
        """Retrieve a case by Case ID."""
        data = self._read_file(self.cases_file)
        return data.get(case_id)

    def list_cases(self) -> List[dict]:
        """Return a list of all stored cases."""
        data = self._read_file(self.cases_file)
        return list(data.values())

    # --- Evidence Methods ---
    def save_evidence(self, evidence_dict: dict) -> None:
        """Save or update evidence metadata in the JSON store."""
        data = self._read_file(self.evidence_file)
        evidence_id = evidence_dict["evidence_id"]
        data[evidence_id] = evidence_dict
        self._write_file(self.evidence_file, data)

    def get_evidence(self, evidence_id: str) -> Optional[dict]:
        """Retrieve evidence metadata by Evidence ID."""
        data = self._read_file(self.evidence_file)
        return data.get(evidence_id)

    def list_evidence_by_case(self, case_id: str) -> List[dict]:
        """Return a list of all evidence items associated with a specific Case ID."""
        data = self._read_file(self.evidence_file)
        return [
            item for item in data.values()
            if item.get("case_id") == case_id
        ]

    # --- Metadata Methods ---
    def save_metadata(self, metadata_dict: dict) -> None:
        """Save or update extracted metadata for an evidence item."""
        data = self._read_file(self.metadata_file)
        evidence_id = metadata_dict["evidence_id"]
        data[evidence_id] = metadata_dict
        self._write_file(self.metadata_file, data)

    def get_metadata(self, evidence_id: str) -> Optional[dict]:
        """Retrieve extracted metadata by Evidence ID."""
        data = self._read_file(self.metadata_file)
        return data.get(evidence_id)

