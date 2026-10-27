"""
Thread-safe background worker execution for long-running forensic operations.
"""

import queue
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.metadata.extractor import MetadataExtractor
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.detection.ela import ELADetector
from digitalshield.detection.deepfake import DeepfakeAssessmentService
from digitalshield.provenance.service import ProvenanceService
from digitalshield.reporting.service import ReportingService
from digitalshield.storage.json_store import JSONStore
from digitalshield.security.audit import AuditLogger


class AnalysisWorker(threading.Thread):
    """
    Background worker that runs the full forensic analysis pipeline on a separate thread.
    Emits atomic progress messages to a queue polled by the main GUI thread.
    """

    def __init__(
        self,
        case_name: str,
        investigator: str,
        description: str,
        image_path: Path,
        msg_queue: queue.Queue,
        base_dir: Optional[Path] = None,
        source_url: Optional[str] = None,
    ):
        super().__init__(daemon=True)
        self.case_name = case_name
        self.investigator = investigator
        self.description = description
        self.image_path = Path(image_path)
        self.msg_queue = msg_queue
        self.base_dir = base_dir
        self.source_url = source_url.strip() if source_url and isinstance(source_url, str) else None

    def run(self):
        try:
            # 1. Initialize existing backend services
            case_mgr = CaseManager(self.base_dir)
            ev_mgr = EvidenceManager(self.base_dir)
            meta_extractor = MetadataExtractor(self.base_dir)
            fp_service = FingerprintService(self.base_dir)
            ela_detector = ELADetector(self.base_dir)
            df_service = DeepfakeAssessmentService(self.base_dir)

            # Step 1: Create Case
            self.msg_queue.put({"type": "step_start", "step": 0, "msg": "Initializing Case..."})
            case = case_mgr.create_case(
                name=self.case_name,
                investigator=self.investigator,
                description=self.description,
                source_url=self.source_url,
            )
            self.msg_queue.put({"type": "step_done", "step": 0, "msg": f"Case created: {case.case_id}"})

            # Step 2: Import & Preserve Evidence
            self.msg_queue.put({"type": "step_start", "step": 1, "msg": "Preserving Evidence in Vault..."})
            evidence = ev_mgr.import_evidence(
                file_path=self.image_path,
                case_id=case.case_id,
                source_url=self.source_url,
            )
            self.msg_queue.put({"type": "step_done", "step": 1, "msg": f"Evidence preserved ({evidence.evidence_id})"})

            # Optional: Record reported source URL in provenance system if supplied
            prov_records = []
            if self.source_url:
                try:
                    prov_service = ProvenanceService(self.base_dir)
                    rec = prov_service.record_provenance(
                        evidence_id=evidence.evidence_id,
                        source_url=self.source_url,
                        notes="Public source URL supplied by investigator during intake.",
                        fetch_online=False,
                    )
                    prov_records.append(rec.to_dict())
                except Exception:
                    pass

            # Step 3: Extract Metadata & EXIF
            self.msg_queue.put({"type": "step_start", "step": 2, "msg": "Analyzing Technical & EXIF Metadata..."})
            meta_result = meta_extractor.extract(evidence.evidence_id)
            self.msg_queue.put({"type": "step_done", "step": 2, "msg": "Metadata analysis complete"})

            # Step 4: Perceptual Fingerprints
            self.msg_queue.put({"type": "step_start", "step": 3, "msg": "Generating Perceptual Fingerprints (aHash, dHash, pHash)..."})
            fp_result = fp_service.generate_fingerprints(evidence.evidence_id)
            self.msg_queue.put({"type": "step_done", "step": 3, "msg": "Fingerprints generated"})

            # Step 5: Error Level Analysis (ELA)
            self.msg_queue.put({"type": "step_start", "step": 4, "msg": "Running Error Level Analysis (ELA)..."})
            ela_result = ela_detector.analyze_evidence(evidence.evidence_id)
            self.msg_queue.put({"type": "step_done", "step": 4, "msg": "ELA analysis complete"})

            # Step 6: Deepfake & Synthetic Media Assessment
            self.msg_queue.put({"type": "step_start", "step": 5, "msg": "Evaluating Synthetic Media Indicators..."})
            df_result = df_service.assess_evidence(evidence.evidence_id)
            self.msg_queue.put({"type": "step_done", "step": 5, "msg": "Synthetic media assessment complete"})

            # Step 7: Automatic Reverse Image Search & Public Web Discovery
            self.msg_queue.put({"type": "step_start", "step": 6, "msg": "Running Automatic Reverse Image Search & Public Web Discovery..."})
            wd_session = None
            wd_results = []
            try:
                from digitalshield.web_discovery.service import WebDiscoveryService
                wd_service = WebDiscoveryService(self.base_dir)
                wd_session = wd_service.run_search(evidence.evidence_id)
                wd_results = [r.to_dict() for r in wd_service.list_results_by_session(wd_session.session_id)]
                self.msg_queue.put({"type": "step_done", "step": 6, "msg": f"Discovery complete: {len(wd_results)} source(s) found"})
            except Exception as wde:
                self.msg_queue.put({"type": "step_done", "step": 6, "msg": f"Web discovery note: {str(wde)[:50]}"})

            # Assemble complete data bundle for GUI display
            payload = {
                "case": case,
                "evidence": evidence,
                "metadata": meta_result,
                "fingerprints": fp_result,
                "ela": ela_result,
                "deepfake": df_result,
                "provenance": prov_records,
                "source_url": self.source_url,
                "web_discovery_session": wd_session.to_dict() if wd_session else None,
                "web_discovery_results": wd_results,
            }
            self.msg_queue.put({"type": "complete", "data": payload})

        except Exception as e:
            self.msg_queue.put({"type": "error", "error": str(e)})


class ReportWorker(threading.Thread):
    """
    Background worker that generates forensic reports without freezing the GUI.
    """

    def __init__(
        self,
        case_id: str,
        formats: Optional[List[str]],
        msg_queue: queue.Queue,
        base_dir: Optional[Path] = None,
    ):
        super().__init__(daemon=True)
        self.case_id = case_id
        self.formats = formats or ["markdown", "html", "pdf"]
        self.msg_queue = msg_queue
        self.base_dir = base_dir

    def run(self):
        try:
            service = ReportingService(self.base_dir)
            record, file_map = service.generate_report(
                case_id=self.case_id,
                formats=self.formats,
            )
            self.msg_queue.put({
                "type": "report_success",
                "record": record,
                "file_map": {fmt: str(path) for fmt, path in file_map.items()},
            })
        except Exception as e:
            self.msg_queue.put({"type": "report_error", "error": str(e)})


class WebDiscoveryWorker(threading.Thread):
    """
    Background worker that runs Google Cloud Vision Web Detection source discovery
    without freezing the Tkinter GUI thread.

    Emits messages to msg_queue:
      {"type": "wd_start"}
      {"type": "wd_complete", "session": <WebDiscoverySession dict>, "results": [<WebDiscoveryResult dict>, ...]}
      {"type": "wd_error", "error": <str>}

    SECURITY: never logs or exposes the API key.
    FORENSICS: never modifies original evidence.
    """

    def __init__(
        self,
        evidence_id: str,
        msg_queue: queue.Queue,
        base_dir: Optional[Path] = None,
    ):
        super().__init__(daemon=True)
        self.evidence_id = evidence_id
        self.msg_queue = msg_queue
        self.base_dir = base_dir

    def run(self):
        try:
            from digitalshield.web_discovery.service import WebDiscoveryService
            self.msg_queue.put({"type": "wd_start"})
            service = WebDiscoveryService(self.base_dir)
            session = service.run_search(self.evidence_id)
            results = service.list_results_by_session(session.discovery_id)
            self.msg_queue.put({
                "type": "wd_complete",
                "session": session.to_dict(),
                "results": [r.to_dict() for r in results],
            })
        except Exception as e:
            self.msg_queue.put({"type": "wd_error", "error": str(e)})
