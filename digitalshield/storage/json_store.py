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
        self.metadata_file = self.base_dir / "metadata.json"
        self.fingerprints_file = self.base_dir / "fingerprints.json"
        self.ela_file = self.base_dir / "ela.json"
        self.deepfake_file = self.base_dir / "deepfake.json"
        self.provenance_file = self.base_dir / "provenance.json"
        self.base_dir.mkdir(parents=True, exist_ok=True)
        if not self.cases_file.exists():
            self._write_file(self.cases_file, {})
        if not self.evidence_file.exists():
            self._write_file(self.evidence_file, {})
        if not self.metadata_file.exists():
            self._write_file(self.metadata_file, {})
        if not self.fingerprints_file.exists():
            self._write_file(self.fingerprints_file, {})
        if not self.ela_file.exists():
            self._write_file(self.ela_file, {})
        if not self.deepfake_file.exists():
            self._write_file(self.deepfake_file, {})
        if not self.provenance_file.exists():
            self._write_file(self.provenance_file, {})

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

    # --- Fingerprint Methods ---
    def save_fingerprints(self, fingerprint_dict: dict) -> None:
        """Save or update extracted perceptual fingerprints for an evidence item."""
        data = self._read_file(self.fingerprints_file)
        evidence_id = fingerprint_dict["evidence_id"]
        data[evidence_id] = fingerprint_dict
        self._write_file(self.fingerprints_file, data)

    def get_fingerprints(self, evidence_id: str) -> Optional[dict]:
        """Retrieve extracted perceptual fingerprints by Evidence ID."""
        data = self._read_file(self.fingerprints_file)
        return data.get(evidence_id)

    def list_fingerprints(self) -> List[dict]:
        """Return a list of all stored perceptual fingerprint records."""
        data = self._read_file(self.fingerprints_file)
        return list(data.values())

    # --- ELA Detection Methods ---
    def save_ela(self, ela_dict: dict) -> None:
        """Save or update ELA detection results for an evidence item."""
        data = self._read_file(self.ela_file)
        evidence_id = ela_dict["evidence_id"]
        data[evidence_id] = ela_dict
        self._write_file(self.ela_file, data)

    def get_ela(self, evidence_id: str) -> Optional[dict]:
        """Retrieve ELA detection results by Evidence ID."""
        data = self._read_file(self.ela_file)
        return data.get(evidence_id)

    def list_ela(self) -> List[dict]:
        """Return a list of all stored ELA detection records."""
        data = self._read_file(self.ela_file)
        return list(data.values())

    # --- Deepfake Assessment Methods ---
    def save_deepfake(self, deepfake_dict: dict) -> None:
        """Save or update deepfake assessment results for an evidence item."""
        data = self._read_file(self.deepfake_file)
        evidence_id = deepfake_dict["evidence_id"]
        data[evidence_id] = deepfake_dict
        self._write_file(self.deepfake_file, data)

    def get_deepfake(self, evidence_id: str) -> Optional[dict]:
        """Retrieve deepfake assessment results by Evidence ID."""
        data = self._read_file(self.deepfake_file)
        return data.get(evidence_id)

    def list_deepfake(self) -> List[dict]:
        """Return a list of all stored deepfake assessment records."""
        data = self._read_file(self.deepfake_file)
        return list(data.values())

    # --- Provenance Analysis Methods ---
    def save_provenance(self, provenance_dict: dict) -> None:
        """Save or update provenance record in the JSON store."""
        data = self._read_file(self.provenance_file)
        provenance_id = provenance_dict["provenance_id"]
        data[provenance_id] = provenance_dict
        self._write_file(self.provenance_file, data)

    def get_provenance(self, provenance_id: str) -> Optional[dict]:
        """Retrieve provenance record by Provenance ID."""
        data = self._read_file(self.provenance_file)
        return data.get(provenance_id)

    def list_provenance_by_case(self, case_id: str) -> List[dict]:
        """Return a list of all provenance records associated with a specific Case ID."""
        data = self._read_file(self.provenance_file)
        return [
            item for item in data.values()
            if item.get("case_id") == case_id
        ]

    def list_provenance_by_evidence(self, evidence_id: str) -> List[dict]:
        """Return a list of all provenance records associated with a specific Evidence ID."""
        data = self._read_file(self.provenance_file)
        return [
            item for item in data.values()
            if item.get("evidence_id") == evidence_id
        ]

    def list_provenance(self) -> List[dict]:
        """Return a list of all stored provenance records."""
        data = self._read_file(self.provenance_file)
        return list(data.values())




