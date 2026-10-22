"""
ReportingService coordinating report data compilation, format rendering,
storage, and tamper-evident audit logging.

FORENSIC INTEGRITY RULES:
- Reuses existing CaseManager, EvidenceManager, JSONStore, AuditLogger, and ProvenanceService.
- Never modifies original evidence files or existing audit entries.
- Generates reproducible, neutral reports with explicit probabilistic caveats.
- Output files are strictly local under .digitalshield_data/cases/<case_id>/reports/
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.provenance.service import ProvenanceService
from digitalshield.reporting.models import (
    CaseInfo,
    EvidenceItemReport,
    ReportData,
    ReportMetadata,
    ReportRecord,
)
from digitalshield.reporting.renderers.html_renderer import HTMLRenderer
from digitalshield.reporting.renderers.markdown_renderer import MarkdownRenderer
from digitalshield.reporting.renderers.pdf_renderer import PDFRenderer
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore


class ReportingService:
    """
    Forensic service managing case report aggregation, rendering, and persistence.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.case_manager = CaseManager(self.base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")
        self.provenance_service = ProvenanceService(self.base_dir)

    def _generate_report_id(self) -> str:
        """Generate sequential Report ID in format RPT-YYYY-XXXXXX."""
        year = datetime.now(timezone.utc).strftime("%Y")
        existing_records = self.store.list_reports()

        prefix = f"RPT-{year}-"
        matching_indices = []
        for r in existing_records:
            rid = r.get("report_id", "")
            if rid.startswith(prefix):
                try:
                    num = int(rid.split("-")[-1])
                    matching_indices.append(num)
                except ValueError:
                    pass

        next_idx = max(matching_indices, default=0) + 1
        return f"RPT-{year}-{next_idx:06d}"

    def compile_report_data(self, case_id: str, report_id: Optional[str] = None) -> ReportData:
        """
        Aggregate and structure all forensic data associated with a case.
        Never fabricates missing information.
        """
        case = self.case_manager.get_case(case_id)
        if not case:
            raise ValueError(f"Case ID '{case_id}' does not exist.")

        now_utc = datetime.now(timezone.utc).isoformat()
        if not report_id:
            report_id = self._generate_report_id()

        # 1. Metadata
        report_meta = ReportMetadata(
            report_id=report_id,
            case_id=case.case_id,
            case_name=case.name,
            investigator=case.investigator,
            report_timestamp=now_utc,
            report_version="1.0",
            software_version="0.1.0",
            tool_name="DigitalShield",
        )

        # 2. Case Info
        case_info = CaseInfo(
            case_id=case.case_id,
            name=case.name,
            investigator=case.investigator,
            description=case.description,
            source_url=getattr(case, "source_url", None),
            created_at=case.created_at,
            status=case.status,
            vault_path=case.vault_path,
            evidence_count=case.evidence_count,
        )

        # 3. Evidence Items
        raw_evidence = self.evidence_manager.list_evidence(case_id)
        evidence_items: List[EvidenceItemReport] = []
        metadata_findings: Dict[str, Optional[Dict]] = {}
        fingerprint_findings: Dict[str, Optional[Dict]] = {}
        ela_findings: Dict[str, Optional[Dict]] = {}
        deepfake_findings: Dict[str, Optional[Dict]] = {}
        timelines: Dict[str, Dict] = {}

        for ev in raw_evidence:
            ev_report = EvidenceItemReport(
                evidence_id=ev.evidence_id,
                case_id=ev.case_id,
                original_filename=ev.original_filename,
                stored_filename=ev.stored_filename,
                stored_path=ev.stored_path,
                file_size=ev.file_size,
                mime_type=ev.mime_type,
                source_url=getattr(ev, "source_url", None),
                import_timestamp=ev.import_timestamp,
                sha256=ev.sha256,
                status=ev.status,
            )
            evidence_items.append(ev_report)

            # Retrieve analysis artifacts from JSON store
            meta_res = self.store.get_metadata(ev.evidence_id)
            if meta_res:
                metadata_findings[ev.evidence_id] = meta_res

            fp_res = self.store.get_fingerprints(ev.evidence_id)
            if fp_res:
                fingerprint_findings[ev.evidence_id] = fp_res

            ela_res = self.store.get_ela(ev.evidence_id)
            if ela_res:
                ela_findings[ev.evidence_id] = ela_res

            df_res = self.store.get_deepfake(ev.evidence_id)
            if df_res:
                deepfake_findings[ev.evidence_id] = df_res

            # Retrieve provenance timeline for this evidence item
            try:
                tl = self.provenance_service.get_provenance_timeline(ev.evidence_id)
                timelines[ev.evidence_id] = tl
            except Exception:
                pass

        # 4. Provenance Records for the case
        prov_records = self.store.list_provenance_by_case(case_id)

        # 5. Audit Events
        audit_events = self.audit_logger.get_events_by_case(case_id)

        # 6. Resolve Reported Public Source URL (supplied by investigator)
        rep_url = getattr(case, "source_url", None)
        rep_rec_at = case.created_at if rep_url else None
        rep_status = "Not independently verified." if rep_url else None
        rep_ev_id = evidence_items[0].evidence_id if evidence_items else None

        if not rep_url and evidence_items:
            for ei in evidence_items:
                if getattr(ei, "source_url", None):
                    rep_url = ei.source_url
                    rep_rec_at = ei.import_timestamp
                    rep_status = "Not independently verified."
                    rep_ev_id = ei.evidence_id
                    break

        if not rep_url and prov_records:
            for pr in prov_records:
                if pr.get("source_url"):
                    rep_url = pr.get("source_url")
                    rep_rec_at = pr.get("discovery_timestamp") or case.created_at
                    raw_st = pr.get("source_status") or "Not independently verified."
                    rep_status = raw_st if raw_st.endswith(".") else f"{raw_st}."
                    rep_ev_id = pr.get("evidence_id") or rep_ev_id
                    break

        # 7. Overall Findings Synthesis
        overall_findings = []
        overall_findings.append(f"{len(evidence_items)} digital evidence item(s) preserved in read-only forensic vault with SHA-256 baseline verification.")
        
        if rep_url:
            overall_findings.append(f"Public webpage source URL recorded as reported by investigator: {rep_url} (Verification status: {rep_status or 'Not independently verified'}).")
        if metadata_findings:
            overall_findings.append(f"Technical metadata/EXIF parsed for {len(metadata_findings)} evidence item(s).")
        if fingerprint_findings:
            overall_findings.append(f"Perceptual hash baselines (aHash, dHash, pHash) calculated for {len(fingerprint_findings)} media item(s).")
        if ela_findings:
            overall_findings.append(f"Error Level Analysis (ELA) performed on {len(ela_findings)} evidence item(s) to evaluate compression artifact uniformity.")
        if deepfake_findings:
            overall_findings.append(f"AI-assisted synthetic media assessments executed for {len(deepfake_findings)} evidence item(s).")
        if prov_records:
            overall_findings.append(f"{len(prov_records)} public URL provenance observation(s) recorded for investigative correlation.")

        # 8. Standard Forensic Limitations
        limitations = [
            "Digital evidence items are preserved in read-only vaults; SHA-256 digests represent the baseline state upon ingestion.",
            "The absence of EXIF metadata is standard across social media and messaging platforms and does not prove tampering.",
            "Perceptual hashing measures visual structural similarity and does not establish original authorship, creation, or ownership.",
            "Error Level Analysis (ELA) is a probabilistic indicator and cannot independently prove forgery, tampering, or manipulation.",
            "AI-assisted deepfake assessments are probabilistic indicators and should not be treated as definitive proof of manipulation, identity, authorship, ownership, or criminal responsibility.",
            "Public URL observations reflect publicly visible web states at discovery time and do not establish account ownership or publication dates.",
            "DigitalShield forensic reports provide technical documentation and do not determine legal liability or criminal guilt.",
        ]

        return ReportData(
            metadata=report_meta,
            case_info=case_info,
            evidence_items=evidence_items,
            metadata_findings=metadata_findings,
            fingerprint_findings=fingerprint_findings,
            ela_findings=ela_findings,
            deepfake_findings=deepfake_findings,
            provenance_records=prov_records,
            timelines=timelines,
            audit_events=audit_events,
            overall_findings=overall_findings,
            limitations=limitations,
            investigator_notes=case.description if case.description else None,
            reported_source_url=rep_url,
            reported_source_url_recorded_at=rep_rec_at,
            reported_source_url_status=rep_status,
            reported_source_url_evidence_id=rep_ev_id,
        )

    def generate_report(
        self,
        case_id: str,
        formats: Union[str, List[str]] = "markdown"
    ) -> Tuple[ReportRecord, Dict[str, Path]]:
        """
        Generate forensic reports for a case in specified formats (markdown, html, pdf, all).
        Persists report files under .digitalshield_data/cases/<case_id>/reports/
        Records REPORT_GENERATED in audit.log and updates JSONStore.
        """
        # Normalize requested formats
        if isinstance(formats, str):
            if formats.lower() == "all":
                fmt_list = ["markdown", "html", "pdf"]
            else:
                fmt_list = [f.strip().lower() for f in formats.split(",")]
        else:
            fmt_list = [f.lower() for f in formats]

        valid_formats = {"markdown", "html", "pdf"}
        for f in fmt_list:
            if f not in valid_formats:
                raise ValueError(f"Unsupported report format '{f}'. Supported formats: markdown, html, pdf, all.")

        report_id = self._generate_report_id()
        report_data = self.compile_report_data(case_id, report_id=report_id)

        # Target directory: .digitalshield_data/cases/<case_id>/reports/
        reports_dir = self.base_dir / "cases" / case_id / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        output_paths: Dict[str, Path] = {}
        files_map: Dict[str, str] = {}

        for fmt in fmt_list:
            if fmt == "markdown":
                md_content = MarkdownRenderer.render(report_data)
                md_path = reports_dir / f"report_{report_id}.md"
                with open(md_path, "w", encoding="utf-8") as f:
                    f.write(md_content)
                output_paths["markdown"] = md_path
                files_map["markdown"] = str(md_path)

            elif fmt == "html":
                html_content = HTMLRenderer.render(report_data)
                html_path = reports_dir / f"report_{report_id}.html"
                with open(html_path, "w", encoding="utf-8") as f:
                    f.write(html_content)
                output_paths["html"] = html_path
                files_map["html"] = str(html_path)

            elif fmt == "pdf":
                pdf_path = reports_dir / f"report_{report_id}.pdf"
                PDFRenderer.render(report_data, pdf_path)
                output_paths["pdf"] = pdf_path
                files_map["pdf"] = str(pdf_path)

            else:
                pass

        record = ReportRecord(
            report_id=report_id,
            case_id=case_id,
            generation_timestamp=report_data.metadata.report_timestamp,
            formats_generated=fmt_list,
            files=files_map,
            status="GENERATED"
        )

        # 1. Save in central JSONStore
        self.store.save_report(record.to_dict())

        # 2. Record audit log: REPORT_GENERATED
        self.audit_logger.log_event(
            action="REPORT_GENERATED",
            details={
                "report_id": report_id,
                "case_id": case_id,
                "formats": fmt_list,
                "files": files_map,
            },
            actor="DigitalShield Reporting Engine"
        )

        return record, output_paths

    def get_report(self, report_id: str) -> Optional[ReportRecord]:
        """Retrieve stored report record by Report ID."""
        data = self.store.get_report(report_id)
        if data:
            return ReportRecord.from_dict(data)
        return None

    def list_reports_by_case(self, case_id: str) -> List[ReportRecord]:
        """List all reports associated with a specific Case ID."""
        records = self.store.list_reports_by_case(case_id)
        return [ReportRecord.from_dict(r) for r in records]

    def list_reports(self) -> List[ReportRecord]:
        """List all stored reports across cases."""
        records = self.store.list_reports()
        return [ReportRecord.from_dict(r) for r in records]
