"""
Service orchestrator for Google Lens Reverse Image Search Workflow
(Investigator-Assisted Public Reverse Image Search).

FORENSIC INTEGRITY:
- Google Lens does not provide an official public general API; searching is conducted
  by opening the official Google Lens portal (https://lens.google.com/) for manual investigator upload.
- Evidence files are never modified, sent to unofficial scrapers, or altered in any way.
- Results recorded by the investigator are validated (HTTP/HTTPS only, no SSRF/file:// bypass),
  persisted to JSONStore, and logged in the append-only cryptographic audit trail.
"""

import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore
from digitalshield.web_discovery.lens_models import (
    GOOGLE_LENS_CATEGORIES,
    GoogleLensResult,
    GoogleLensSession,
    detect_platform_name,
    validate_http_url,
)

GOOGLE_LENS_URL = "https://lens.google.com/"


class GoogleLensService:
    """
    Manages investigator-assisted Google Lens reverse image search sessions
    and recorded candidate results.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = Path(base_dir) if base_dir else Path(".digitalshield_data")
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")
        self.evidence_manager = EvidenceManager(self.base_dir)

    # ------------------------------------------------------------- ID Generators
    def _generate_session_id(self) -> str:
        sessions = self.store.list_web_discovery_sessions()
        # Find highest GLS counter
        max_num = 0
        current_year = datetime.now(timezone.utc).year
        for s in sessions:
            sid = s.get("session_id") or s.get("discovery_id", "")
            if sid.startswith(f"GLS-{current_year}-"):
                try:
                    num = int(sid.split("-")[-1])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
        return f"GLS-{current_year}-{max_num + 1:06d}"

    def _generate_result_id(self) -> str:
        results = self.store.list_web_discovery_results()
        max_num = 0
        current_year = datetime.now(timezone.utc).year
        for r in results:
            rid = r.get("result_id", "")
            if rid.startswith(f"GLR-{current_year}-"):
                try:
                    num = int(rid.split("-")[-1])
                    if num > max_num:
                        max_num = num
                except ValueError:
                    pass
        return f"GLR-{current_year}-{max_num + 1:06d}"

    # ------------------------------------------------------------- Session Ops
    def initiate_lens_search(self, evidence_id: str) -> Tuple[GoogleLensSession, Path]:
        """
        Initiate a Google Lens search workflow for an evidence item:
        1. Verifies the evidence exists in the vault (read-only verification).
        2. Generates an active GoogleLensSession.
        3. Opens the official Google Lens portal in the system default browser.
        4. Logs GOOGLE_LENS_SEARCH_INITIATED in the audit log.

        Returns (session, evidence_vault_path).
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        vault_path = Path(evidence.stored_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Preserved evidence file not found at: {vault_path}")

        session_id = self._generate_session_id()
        session = GoogleLensSession(
            session_id=session_id,
            evidence_id=evidence_id,
            case_id=evidence.case_id,
            provider="Google Lens (Manual)",
            search_url=GOOGLE_LENS_URL,
            created_at=datetime.now(timezone.utc).isoformat(),
            status="ACTIVE",
            results_count=0,
        )

        # Persist session to JSONStore (compatible with web_discovery_sessions schema)
        session_dict = session.to_dict()
        session_dict["discovery_id"] = session.session_id  # alias for backwards compatibility
        self.store.save_web_discovery_session(session_dict)

        # Also store under case analysis folder
        case_dir = self.base_dir / "cases" / evidence.case_id / "analysis" / "google_lens"
        case_dir.mkdir(parents=True, exist_ok=True)
        with open(case_dir / f"session_{session_id}.json", "w", encoding="utf-8") as f:
            import json
            json.dump(session_dict, f, indent=2)

        # Open official Google Lens portal
        try:
            webbrowser.open(GOOGLE_LENS_URL)
        except Exception:
            pass

        # Audit logging
        self.audit_logger.log_event(
            action="GOOGLE_LENS_SEARCH_INITIATED",
            details={
                "session_id": session_id,
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "provider": "Google Lens (Manual)",
                "search_portal": GOOGLE_LENS_URL,
            },
            actor="Investigator (Assisted by DigitalShield)",
        )

        return session, vault_path

    def open_google_lens_portal(self) -> bool:
        """Open https://lens.google.com/ in the default browser."""
        try:
            return webbrowser.open(GOOGLE_LENS_URL)
        except Exception:
            return False

    # ------------------------------------------------------------- Result Ops
    def record_match_result(
        self,
        session_id: str,
        source_url: str,
        platform_name: Optional[str] = None,
        page_title: Optional[str] = None,
        media_url: Optional[str] = None,
        search_category: str = "Visually similar image",
        investigator_notes: Optional[str] = None,
    ) -> GoogleLensResult:
        """
        Record an investigator-discovered match from Google Lens.
        Validates URL scheme (HTTP/HTTPS only; blocks file://, ftp://),
        associates with case & evidence, updates session count, and logs audit trail.
        """
        session_data = self.store.get_web_discovery_session(session_id)
        if not session_data:
            raise ValueError(f"Google Lens session '{session_id}' not found.")

        # Validate URLs
        valid_source = validate_http_url(source_url, field_name="Matching webpage URL")
        valid_media = validate_http_url(media_url, field_name="Matching image URL") if media_url else None

        # Autodetect platform name if empty
        if not platform_name or not platform_name.strip():
            platform_name = detect_platform_name(valid_source)
        else:
            platform_name = platform_name.strip()

        # Validate category
        if search_category not in GOOGLE_LENS_CATEGORIES:
            search_category = "Other public webpage"

        result_id = self._generate_result_id()
        case_id = session_data.get("case_id", "")
        evidence_id = session_data.get("evidence_id", "")

        result = GoogleLensResult(
            result_id=result_id,
            session_id=session_id,
            evidence_id=evidence_id,
            case_id=case_id,
            source_url=valid_source,
            platform_name=platform_name,
            page_title=page_title.strip() if page_title else None,
            media_url=valid_media,
            search_category=search_category,
            search_provider="Google Lens (Manual)",
            recorded_at=datetime.now(timezone.utc).isoformat(),
            investigator_notes=investigator_notes.strip() if investigator_notes else None,
        )

        # Persist to JSONStore (compatible with web_discovery_results structure)
        res_dict = result.to_dict()
        res_dict["discovery_id"] = session_id  # alias
        res_dict["domain"] = platform_name
        res_dict["status"] = "Source discovered"
        res_dict["provider_match_type"] = search_category
        self.store.save_web_discovery_result(res_dict)

        # Save to case analysis folder
        case_dir = self.base_dir / "cases" / case_id / "analysis" / "google_lens"
        case_dir.mkdir(parents=True, exist_ok=True)
        with open(case_dir / f"result_{result_id}.json", "w", encoding="utf-8") as f:
            import json
            json.dump(res_dict, f, indent=2)

        # Update session result count
        current_results = self.list_results_by_session(session_id)
        session_data["results_count"] = len(current_results)
        session_data["status"] = "COMPLETED"
        self.store.save_web_discovery_session(session_data)

        # Audit event
        self.audit_logger.log_event(
            action="GOOGLE_LENS_RESULT_RECORDED",
            details={
                "result_id": result_id,
                "session_id": session_id,
                "evidence_id": evidence_id,
                "case_id": case_id,
                "source_url": valid_source,
                "platform": platform_name,
                "category": search_category,
            },
            actor="Investigator",
        )

        return result

    def mark_session_no_results(self, session_id: str, notes: Optional[str] = None) -> GoogleLensSession:
        """Mark a Google Lens session as having completed with no matches found."""
        session_data = self.store.get_web_discovery_session(session_id)
        if not session_data:
            raise ValueError(f"Session '{session_id}' not found.")

        session_data["status"] = "NO_RESULTS"
        session_data["investigator_notes"] = notes or "Investigator searched Google Lens; no matching sources observed."
        self.store.save_web_discovery_session(session_data)

        self.audit_logger.log_event(
            action="GOOGLE_LENS_NO_RESULTS_RECORDED",
            details={
                "session_id": session_id,
                "evidence_id": session_data.get("evidence_id"),
                "case_id": session_data.get("case_id"),
                "notes": session_data["investigator_notes"],
            },
            actor="Investigator",
        )
        return GoogleLensSession.from_dict(session_data)

    def list_sessions_by_evidence(self, evidence_id: str) -> List[dict]:
        """List all Google Lens / web discovery sessions for an evidence item."""
        return self.store.list_web_discovery_sessions_by_evidence(evidence_id)

    def list_results_by_session(self, session_id: str) -> List[dict]:
        """List all results recorded under a given session ID."""
        return self.store.list_web_discovery_results_by_session(session_id)

    def list_results_by_case(self, case_id: str) -> List[dict]:
        """List all results recorded for a case."""
        return self.store.list_web_discovery_results_by_case(case_id)
