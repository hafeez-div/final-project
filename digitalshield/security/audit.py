"""
Audit logging subsystem providing append-only, tamper-evident forensic event logging.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


class AuditLogger:
    """
    Append-only audit logger that records forensic operations with cryptographic entry digests.
    """

    def __init__(self, log_path: Optional[Path] = None):
        if log_path is None:
            log_path = Path(".digitalshield_data") / "audit.log"
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _get_previous_hash(self) -> str:
        """Read the last entry hash from the log file, or return genesis hash."""
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return "0" * 64

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        entry = json.loads(line)
                        return entry.get("entry_hash", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def log_event(self, action: str, details: Dict[str, Any], actor: str = "System") -> Dict[str, Any]:
        """
        Record a forensic action into the append-only audit log.
        """
        prev_hash = self._get_previous_hash()
        timestamp = datetime.now(timezone.utc).isoformat()

        payload = {
            "timestamp": timestamp,
            "action": action,
            "actor": actor,
            "details": details,
            "previous_hash": prev_hash
        }

        # Calculate entry hash
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        entry_hash = hashlib.sha256(raw_bytes).hexdigest()
        payload["entry_hash"] = entry_hash

        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload) + "\n")

        return payload
