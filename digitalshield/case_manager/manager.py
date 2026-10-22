"""
CaseManager subsystem handling case creation, vault setup, and lifecycle operations.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from digitalshield.case_manager.models import Case
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore


class CaseManager:
    """
    Manager class coordinating case creation, directory setup, storage, and audit logging.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")

    def _generate_case_id(self) -> str:
        """Generate next sequential case ID in format DS-YYYY-XXXXXX."""
        year = datetime.now(timezone.utc).strftime("%Y")
        existing_cases = self.store.list_cases()
        
        prefix = f"DS-{year}-"
        matching_indices = []
        for c in existing_cases:
            cid = c.get("case_id", "")
            if cid.startswith(prefix):
                try:
                    num = int(cid.split("-")[-1])
                    matching_indices.append(num)
                except ValueError:
                    pass

        next_idx = max(matching_indices, default=0) + 1
        return f"DS-{year}-{next_idx:06d}"

    def create_case(
        self,
        name: str,
        investigator: str = "Unassigned",
        description: str = "",
        custom_case_id: Optional[str] = None,
        source_url: Optional[str] = None,
    ) -> Case:
        """
        Create a new forensic case, set up local vault directory, save to storage, and log audit event.
        """
        if not name or not name.strip():
            raise ValueError("Case name cannot be empty.")

        case_id = custom_case_id or self._generate_case_id()

        # Check if case ID already exists
        if self.store.get_case(case_id):
            raise ValueError(f"Case with ID '{case_id}' already exists.")

        vault_dir = self.base_dir / "cases" / case_id
        evidence_dir = vault_dir / "evidence"
        reports_dir = vault_dir / "reports"

        # Create vault directories
        evidence_dir.mkdir(parents=True, exist_ok=True)
        reports_dir.mkdir(parents=True, exist_ok=True)

        cleaned_url = source_url.strip() if source_url and isinstance(source_url, str) else None

        case = Case(
            case_id=case_id,
            name=name.strip(),
            investigator=investigator.strip() if investigator else "Unassigned",
            description=description.strip() if description else "",
            source_url=cleaned_url,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="OPEN",
            vault_path=str(vault_dir.resolve()),
            evidence_count=0
        )

        # Persist case
        self.store.save_case(case.to_dict())

        # Audit log creation
        audit_details = {
            "case_id": case.case_id,
            "name": case.name,
            "investigator": case.investigator,
            "vault_path": case.vault_path,
        }
        if case.source_url:
            audit_details["source_url"] = case.source_url

        self.audit_logger.log_event(
            action="CASE_CREATED",
            details=audit_details,
            actor=case.investigator
        )

        return case

    def get_case(self, case_id: str) -> Optional[Case]:
        """Retrieve case by ID."""
        data = self.store.get_case(case_id)
        if data:
            return Case.from_dict(data)
        return None

    def list_cases(self) -> List[Case]:
        """List all cases."""
        data_list = self.store.list_cases()
        return [Case.from_dict(d) for d in data_list]

    def increment_evidence_count(self, case_id: str) -> None:
        """Increment the evidence count associated with a case."""
        case_data = self.store.get_case(case_id)
        if case_data:
            case_data["evidence_count"] = case_data.get("evidence_count", 0) + 1
            self.store.save_case(case_data)
