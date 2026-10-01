"""
EvidenceManager subsystem handling file validation, chunked SHA-256 hashing, vault preservation, and evidence manifests.
"""

import hashlib
import json
import mimetypes
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.models import Evidence
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore

# Standard supported extensions mapping to primary MIME types
SUPPORTED_EXTENSIONS: Dict[str, str] = {
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".webp": "image/webp",
    ".gif": "image/gif",
    ".mp4": "video/mp4",
    ".mov": "video/quicktime",
    ".avi": "video/x-msvideo",
    ".txt": "text/plain",
    ".pdf": "application/pdf"
}

CHUNK_SIZE = 65536  # 64 KB chunks for memory-safe hashing


class EvidenceManager:
    """
    Manager class coordinating evidence ingestion, chunked SHA-256 calculation, read-only vault preservation, and manifests.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.case_manager = CaseManager(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")

    @staticmethod
    def calculate_sha256(file_path: Path) -> str:
        """
        Compute SHA-256 digest of a file in 64 KB chunks to prevent memory overhead.
        """
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def infer_mime_type(file_path: Path) -> str:
        """
        Infer MIME type from file header magic bytes when accessible,
        falling back to the supported extensions map and mimetypes module.
        """
        p = Path(file_path)
        if p.exists() and p.is_file() and p.stat().st_size >= 4:
            try:
                with open(p, "rb") as f:
                    header = f.read(32)
                if header.startswith(b"\x89PNG\r\n\x1a\n"):
                    return "image/png"
                if header.startswith(b"\xff\xd8\xff"):
                    return "image/jpeg"
                if header.startswith(b"GIF87a") or header.startswith(b"GIF89a"):
                    return "image/gif"
                if len(header) >= 12 and header.startswith(b"RIFF") and header[8:12] == b"WEBP":
                    return "image/webp"
                if header.startswith(b"%PDF"):
                    return "application/pdf"
            except Exception:
                pass

        ext = p.suffix.lower()
        if ext in SUPPORTED_EXTENSIONS:
            return SUPPORTED_EXTENSIONS[ext]
        mime, _ = mimetypes.guess_type(str(p))
        return mime or "application/octet-stream"

    def _generate_evidence_id(self) -> str:
        """Generate next sequential evidence ID in format EVD-YYYY-XXXXXX."""
        year = datetime.now(timezone.utc).strftime("%Y")
        all_cases = self.store.list_cases()
        all_evidence = []
        for c in all_cases:
            all_evidence.extend(self.store.list_evidence_by_case(c["case_id"]))

        prefix = f"EVD-{year}-"
        matching_indices = []
        for e in all_evidence:
            eid = e.get("evidence_id", "")
            if eid.startswith(prefix):
                try:
                    num = int(eid.split("-")[-1])
                    matching_indices.append(num)
                except ValueError:
                    pass

        next_idx = max(matching_indices, default=0) + 1
        return f"EVD-{year}-{next_idx:06d}"

    def _update_vault_manifest(self, vault_evidence_dir: Path, evidence_dict: dict) -> None:
        """Maintain evidence_manifest.json inside the case vault evidence directory."""
        manifest_file = vault_evidence_dir / "evidence_manifest.json"
        manifest_data = []

        if manifest_file.exists():
            try:
                with open(manifest_file, "r", encoding="utf-8") as f:
                    manifest_data = json.load(f)
            except Exception:
                manifest_data = []

        manifest_data.append({
            "evidence_id": evidence_dict["evidence_id"],
            "case_id": evidence_dict["case_id"],
            "filename": evidence_dict["original_filename"],
            "file_size": evidence_dict["file_size"],
            "mime_type": evidence_dict["mime_type"],
            "import_timestamp": evidence_dict["import_timestamp"],
            "sha256": evidence_dict["sha256"]
        })

        # Temporarily grant write permissions if manifest file exists and is read-only
        if manifest_file.exists():
            try:
                os.chmod(manifest_file, 0o644)
            except Exception:
                pass

        with open(manifest_file, "w", encoding="utf-8") as f:
            json.dump(manifest_data, f, indent=2)

        # Lock manifest as read-only
        try:
            os.chmod(manifest_file, 0o444)
        except Exception:
            pass

    def import_evidence(self, file_path: Path, case_id: str) -> Evidence:
        """
        Ingest a file into a case evidence vault with read-only protection, SHA-256 calculation, and audit logging.
        """
        source_path = Path(file_path)

        # 1. File existence check
        if not source_path.exists() or not source_path.is_file():
            raise FileNotFoundError(f"File not found or invalid: {source_path}")

        # 2. Extension validation
        ext = source_path.suffix.lower()
        if ext not in SUPPORTED_EXTENSIONS:
            allowed = ", ".join(sorted(SUPPORTED_EXTENSIONS.keys()))
            raise ValueError(f"Unsupported file format '{ext}'. Allowed formats: {allowed}")

        # 3. Case ID existence check
        case_obj = self.case_manager.get_case(case_id)
        if not case_obj:
            raise ValueError(f"Case ID '{case_id}' does not exist.")

        # 4. Chunked SHA-256 hash computation
        sha256_hash = self.calculate_sha256(source_path)
        file_size = source_path.stat().st_size
        mime_type = self.infer_mime_type(source_path)

        # 5. Duplicate check within case
        existing = self.store.list_evidence_by_case(case_id)
        for item in existing:
            if item.get("sha256") == sha256_hash:
                raise ValueError(
                    f"Duplicate evidence import rejected: File with SHA-256 hash '{sha256_hash[:12]}...' already exists in case '{case_id}'."
                )

        # 6. Generate Evidence ID and target paths
        evidence_id = self._generate_evidence_id()
        vault_evidence_dir = Path(case_obj.vault_path) / "evidence"
        vault_evidence_dir.mkdir(parents=True, exist_ok=True)

        stored_filename = f"{evidence_id}_{source_path.name}"
        preserved_path = vault_evidence_dir / stored_filename

        # 7. Preserve file copy into vault (NEVER modify original)
        shutil.copy2(source_path, preserved_path)

        # 8. Lock preserved copy as read-only
        try:
            os.chmod(preserved_path, 0o444)
        except Exception:
            pass

        # 9. Create Evidence model
        evidence = Evidence(
            evidence_id=evidence_id,
            case_id=case_id,
            original_filename=source_path.name,
            stored_filename=stored_filename,
            stored_path=str(preserved_path.resolve()),
            file_size=file_size,
            mime_type=mime_type,
            import_timestamp=datetime.now(timezone.utc).isoformat(),
            sha256=sha256_hash,
            status="PRESERVED"
        )

        # 10. Persist metadata & update case count
        self.store.save_evidence(evidence.to_dict())
        self.case_manager.increment_evidence_count(case_id)

        # 11. Update vault evidence manifest
        self._update_vault_manifest(vault_evidence_dir, evidence.to_dict())

        # 12. Log audit events
        self.audit_logger.log_event(
            action="EVIDENCE_IMPORTED",
            details={
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "original_filename": evidence.original_filename,
                "stored_filename": evidence.stored_filename,
                "file_size": evidence.file_size,
                "mime_type": evidence.mime_type,
                "sha256": evidence.sha256
            },
            actor=case_obj.investigator
        )

        self.audit_logger.log_event(
            action="SHA256_GENERATED",
            details={
                "evidence_id": evidence.evidence_id,
                "sha256": evidence.sha256,
                "chunk_size_bytes": CHUNK_SIZE
            },
            actor="DigitalShield Forensic Engine"
        )

        return evidence

    def list_evidence(self, case_id: str) -> List[Evidence]:
        """List all evidence items ingested into a specific case."""
        case_obj = self.case_manager.get_case(case_id)
        if not case_obj:
            raise ValueError(f"Case ID '{case_id}' does not exist.")

        records = self.store.list_evidence_by_case(case_id)
        return [Evidence.from_dict(r) for r in records]

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence item by Evidence ID."""
        data = self.store.get_evidence(evidence_id)
        if data:
            return Evidence.from_dict(data)
        return None
