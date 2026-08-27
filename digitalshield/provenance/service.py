"""
ProvenanceService coordinating public URL provenance collection, media similarity verification,
provenance timeline construction, storage, and audit logging.

FORENSIC INTEGRITY & ETHICAL RULES:
- Strictly defensive and evidence-oriented.
- Operates ONLY on publicly accessible HTTP/HTTPS targets.
- Zero authentication, credential collection, private account access, or doxxing.
- Reuses existing EvidenceManager, FingerprintService, JSONStore, and AuditLogger.
- NEVER modifies original evidence.
- Uses neutral terminology: "Reported source", "Observed account", "Publicly observed source",
  "Investigative lead", "Evidence-supported association".
"""

import io
import json
import os
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import imagehash
from PIL import Image

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.provenance.client import SafePublicClient
from digitalshield.provenance.models import ProvenanceRecord
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore


class ProvenanceService:
    """
    Forensic service managing public URL provenance observation and media similarity matching.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        client: Optional[SafePublicClient] = None
    ):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.fingerprint_service = FingerprintService(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")
        self.client = client if client is not None else SafePublicClient()

    def _generate_provenance_id(self) -> str:
        """Generate sequential Provenance ID in format PRV-YYYY-XXXXXX."""
        year = datetime.now(timezone.utc).strftime("%Y")
        existing_records = self.store.list_provenance()

        prefix = f"PRV-{year}-"
        matching_indices = []
        for r in existing_records:
            pid = r.get("provenance_id", "")
            if pid.startswith(prefix):
                try:
                    num = int(pid.split("-")[-1])
                    matching_indices.append(num)
                except ValueError:
                    pass

        next_idx = max(matching_indices, default=0) + 1
        return f"PRV-{year}-{next_idx:06d}"

    def record_provenance(
        self,
        evidence_id: str,
        source_url: str,
        observed_account_name: Optional[str] = None,
        media_url: Optional[str] = None,
        source_timestamp: Optional[str] = None,
        notes: Optional[str] = None
    ) -> ProvenanceRecord:
        """
        Record a public URL provenance observation and optionally verify media similarity
        against registered evidence using existing FingerprintService.
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        # Validate URL scheme and SSRF safety
        validated_source_url = self.client.validate_url(source_url)
        domain = urllib.parse.urlparse(validated_source_url).netloc

        now_utc = datetime.now(timezone.utc).isoformat()

        source_title: Optional[str] = None
        source_status = "ACCESSIBLE"
        fetched_content: bytes = b""
        content_type: str = ""

        # Fetch public source page
        try:
            status_code, headers, fetched_content = self.client.fetch_public_url(validated_source_url)
            content_type = headers.get("content-type", "")
            if status_code >= 400:
                source_status = f"INACCESSIBLE (HTTP {status_code})"
            else:
                meta = self.client.extract_public_metadata(fetched_content, content_type)
                source_title = meta.get("source_title")
        except Exception as e:
            source_status = f"INACCESSIBLE ({e})"

        similarity_score: Optional[float] = None
        matching_method: Optional[str] = None

        # Check if media comparison is requested or available
        target_media_url = media_url
        if not target_media_url and content_type.startswith("image/"):
            target_media_url = validated_source_url

        if target_media_url:
            val_media_url = self.client.validate_url(target_media_url)
            try:
                if val_media_url == validated_source_url and fetched_content and content_type.startswith("image/"):
                    media_bytes = fetched_content
                else:
                    m_status, m_headers, media_bytes = self.client.fetch_public_url(val_media_url)
                    if m_status >= 400:
                        media_bytes = b""

                if media_bytes:
                    # Open downloaded media buffer with Pillow
                    with Image.open(io.BytesIO(media_bytes)) as pub_img:
                        pub_ahash = str(imagehash.average_hash(pub_img))
                        pub_dhash = str(imagehash.dhash(pub_img))
                        pub_phash = str(imagehash.phash(pub_img))

                        # Retrieve registered evidence perceptual fingerprints using EXISTING FingerprintService
                        ev_fp = self.fingerprint_service.generate_fingerprints(evidence_id)

                        dist_a = FingerprintService.calculate_hamming_distance(pub_ahash, ev_fp.ahash)
                        dist_d = FingerprintService.calculate_hamming_distance(pub_dhash, ev_fp.dhash)
                        dist_p = FingerprintService.calculate_hamming_distance(pub_phash, ev_fp.phash)

                        sim_a = FingerprintService.calculate_normalized_similarity(dist_a, bit_length=64)
                        sim_d = FingerprintService.calculate_normalized_similarity(dist_d, bit_length=64)
                        sim_p = FingerprintService.calculate_normalized_similarity(dist_p, bit_length=64)

                        overall_sim = round((sim_a + sim_d + sim_p) / 3.0, 4)

                        similarity_score = overall_sim
                        matching_method = "pHash + aHash + dHash"

            except Exception as ex:
                notes = f"{notes or ''} [Media retrieval notice: {ex}]".strip()

        # Generate neutral probabilistic assessment phrasing
        if similarity_score is not None:
            if similarity_score >= 0.90:
                assessment = (
                    f"High visual similarity was observed between the registered evidence and the publicly accessible media "
                    f"(similarity score: {similarity_score:.4f}; {matching_method})."
                )
            elif similarity_score >= 0.70:
                assessment = (
                    f"Moderate visual similarity was observed between the registered evidence and the publicly accessible media "
                    f"(similarity score: {similarity_score:.4f}; {matching_method})."
                )
            else:
                assessment = (
                    f"Low visual similarity was observed between the registered evidence and the publicly accessible media "
                    f"(similarity score: {similarity_score:.4f}; {matching_method})."
                )
        else:
            assessment = (
                "Publicly observed source recorded (investigative lead; evidence-supported association)."
            )

        limitations = [
            "Public-source observation does not establish ownership, authorship, or criminal responsibility.",
            "Visual similarity is a probabilistic indicator and does not prove that an account holder uploaded or created the media.",
            "Timestamps reflect observation or visible page claims, not cryptographic proof of original creation date.",
            "Information is derived exclusively from publicly accessible HTTP/HTTPS resources without authentication.",
        ]

        prov_id = self._generate_provenance_id()

        record = ProvenanceRecord(
            provenance_id=prov_id,
            case_id=evidence.case_id,
            evidence_id=evidence.evidence_id,
            source_url=validated_source_url,
            discovery_timestamp=now_utc,
            source_domain=domain,
            source_title=source_title,
            observed_account_name=observed_account_name,
            media_url=target_media_url,
            similarity_score=similarity_score,
            matching_method=matching_method,
            source_status=source_status,
            source_timestamp=source_timestamp,
            notes=notes,
            assessment=assessment,
            limitations=limitations,
            status="COMPLETED"
        )

        # 1. Save in central JSON store
        self.store.save_provenance(record.to_dict())

        # 2. Save in case analysis folder (.digitalshield_data/cases/<case_id>/analysis/)
        case_analysis_dir = self.base_dir / "cases" / evidence.case_id / "analysis"
        case_analysis_dir.mkdir(parents=True, exist_ok=True)
        case_analysis_file = case_analysis_dir / f"provenance_{prov_id}.json"
        with open(case_analysis_file, "w", encoding="utf-8") as f:
            json.dump(record.to_dict(), f, indent=2)

        # 3. Log audit event: PROVENANCE_SOURCE_RECORDED
        self.audit_logger.log_event(
            action="PROVENANCE_SOURCE_RECORDED",
            details={
                "provenance_id": prov_id,
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "source_url": validated_source_url,
                "domain": domain,
                "observed_account": observed_account_name,
            },
            actor="DigitalShield Provenance Engine"
        )

        # Log audit event if media comparison occurred: PROVENANCE_MEDIA_MATCHED
        if similarity_score is not None:
            self.audit_logger.log_event(
                action="PROVENANCE_MEDIA_MATCHED",
                details={
                    "provenance_id": prov_id,
                    "evidence_id": evidence.evidence_id,
                    "case_id": evidence.case_id,
                    "media_url": target_media_url,
                    "similarity_score": similarity_score,
                    "matching_method": matching_method,
                },
                actor="DigitalShield Provenance Engine"
            )

        return record

    def get_provenance_timeline(self, evidence_id: str) -> Dict[str, Any]:
        """
        Build an evidence-supported chronological timeline combining evidence import timestamp,
        public discovery timestamps, and explicit visible source timestamps.
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        records = self.list_provenance_by_evidence(evidence_id)

        timeline_events = []

        # 1. Evidence Ingestion Event
        timeline_events.append({
            "event_type": "EVIDENCE_IMPORTED",
            "timestamp": evidence.import_timestamp,
            "description": f"Evidence '{evidence.original_filename}' imported into vault case {evidence.case_id}.",
            "source": "Local Evidence Vault (SHA-256 Verified)",
            "verification": f"SHA-256: {evidence.sha256[:16]}..."
        })

        # 2. Provenance Discovery Events
        for r in records:
            timeline_events.append({
                "event_type": "PUBLIC_SOURCE_DISCOVERED",
                "timestamp": r.discovery_timestamp,
                "description": f"Public source observed at '{r.source_domain}' (URL: {r.source_url}).",
                "source": r.source_url,
                "observed_account": r.observed_account_name or "Unknown / Unspecified",
                "similarity_score": f"{r.similarity_score * 100:.1f}%" if r.similarity_score is not None else "N/A",
                "assessment": r.assessment
            })

            if r.source_timestamp:
                timeline_events.append({
                    "event_type": "VISIBLE_SOURCE_TIMESTAMP",
                    "timestamp": r.source_timestamp,
                    "description": f"Explicit visible timestamp reported on public page '{r.source_url}'.",
                    "source": r.source_url,
                    "note": "Timestamp reflects visible page claim; not cryptographic proof of creation date."
                })

        # Sort timeline events chronologically by timestamp string
        timeline_events.sort(key=lambda x: str(x.get("timestamp") or ""))

        return {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "original_filename": evidence.original_filename,
            "import_timestamp": evidence.import_timestamp,
            "total_provenance_records": len(records),
            "timeline": timeline_events,
            "disclaimer": (
                "Timeline reflects evidence import and public observation records. "
                "Do not infer original creation date, identity, or authorship without corroborating evidence."
            )
        }

    def get_provenance(self, provenance_id: str) -> Optional[ProvenanceRecord]:
        """Retrieve stored provenance record by Provenance ID."""
        data = self.store.get_provenance(provenance_id)
        if data:
            return ProvenanceRecord.from_dict(data)
        return None

    def list_provenance_by_case(self, case_id: str) -> List[ProvenanceRecord]:
        """List all provenance records associated with a specific Case ID."""
        records = self.store.list_provenance_by_case(case_id)
        return [ProvenanceRecord.from_dict(r) for r in records]

    def list_provenance_by_evidence(self, evidence_id: str) -> List[ProvenanceRecord]:
        """List all provenance records associated with a specific Evidence ID."""
        records = self.store.list_provenance_by_evidence(evidence_id)
        return [ProvenanceRecord.from_dict(r) for r in records]

    def list_provenance(self) -> List[ProvenanceRecord]:
        """List all stored provenance records."""
        records = self.store.list_provenance()
        return [ProvenanceRecord.from_dict(r) for r in records]
