"""
Automatic Web Discovery & Reverse Image Search Service for DigitalShield.

Performs:
1. Automated provider execution (Google Cloud Vision Web Detection) using read-only evidence.
2. Candidate collection & URL deduplication.
3. SSRF-safe public webpage scraping (via Scrapling Selector).
4. Download and perceptual hash verification (aHash, dHash, pHash) against evidence fingerprints.
5. Storage in JSONStore and .digitalshield_data/cases/<case_id>/analysis/web_discovery/.
6. Audit logging using existing AuditLogger.
"""

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import imagehash
from PIL import Image

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.provenance.client import SafePublicClient
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore
from digitalshield.web_discovery.lens_models import detect_platform_name
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.page_enricher import deduplicate_urls, enrich_page, normalize_url
from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider
from digitalshield.web_discovery.vision_provider import (
    CredentialError,
    VisionAPIError,
    VisionWebDetectionProvider,
)

SUPPORTED_IMAGE_MIMES = {
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/webp",
    "image/gif",
}

VIDEO_MIMES = {
    "video/mp4",
    "video/avi",
    "video/quicktime",
    "video/x-matroska",
    "video/webm",
}


class WebDiscoveryService:
    """
    Orchestrates automatic reverse image search, candidate scraping,
    and perceptual hash verification.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        provider: Optional[BaseReverseImageProvider] = None,
        client: Optional[SafePublicClient] = None,
    ):
        if base_dir is None or not isinstance(base_dir, (str, Path)):
            base_dir = Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.fingerprint_service = FingerprintService(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")
        self.provider = provider if provider is not None else VisionWebDetectionProvider()
        self.client = client if client is not None else SafePublicClient()

    # ------------------------------------------------------------- ID Generators
    def _generate_session_id(self) -> str:
        year = datetime.now(timezone.utc).strftime("%Y")
        prefix = f"WDS-{year}-"
        existing = self.store.list_web_discovery_sessions()
        indices = []
        for s in existing:
            sid = s.get("session_id") or s.get("discovery_id", "")
            if sid.startswith(prefix):
                try:
                    indices.append(int(sid.split("-")[-1]))
                except ValueError:
                    pass
        return f"WDS-{year}-{max(indices, default=0) + 1:06d}"

    def _generate_result_id(self, session_results: List) -> str:
        year = datetime.now(timezone.utc).strftime("%Y")
        prefix = f"WDR-{year}-"
        existing_global = self.store.list_web_discovery_results()
        indices = []
        for r in existing_global:
            rid = r.get("result_id", "")
            if rid.startswith(prefix):
                try:
                    indices.append(int(rid.split("-")[-1]))
                except ValueError:
                    pass
        for r in session_results:
            rid = r.result_id if hasattr(r, "result_id") else r.get("result_id", "")
            if rid.startswith(prefix):
                try:
                    indices.append(int(rid.split("-")[-1]))
                except ValueError:
                    pass
        return f"WDR-{year}-{max(indices, default=0) + 1:06d}"

    # ----------------------------------------------- Perceptual Comparison
    def _compare_remote_image(
        self, media_url: str, evidence_id: str
    ) -> Tuple[Optional[float], Optional[str], Optional[int], Optional[int], Optional[int], str]:
        """
        Download a remote candidate image and compare it against evidence perceptual hashes.
        Returns:
            (similarity_score, method, dist_a, dist_d, dist_p, classification)
        """
        try:
            validated = self.client.validate_url(media_url)
            status, _hdrs, media_bytes = self.client.fetch_public_url(validated)
            if status >= 400 or not media_bytes:
                return None, None, None, None, None, "Unable to verify"

            with Image.open(io.BytesIO(media_bytes)) as pub_img:
                pub_a = str(imagehash.average_hash(pub_img))
                pub_d = str(imagehash.dhash(pub_img))
                pub_p = str(imagehash.phash(pub_img))

            ev_fp = self.fingerprint_service.generate_fingerprints(evidence_id)
            dist_a = FingerprintService.calculate_hamming_distance(pub_a, ev_fp.ahash)
            dist_d = FingerprintService.calculate_hamming_distance(pub_d, ev_fp.dhash)
            dist_p = FingerprintService.calculate_hamming_distance(pub_p, ev_fp.phash)

            sim_a = FingerprintService.calculate_normalized_similarity(dist_a, bit_length=64)
            sim_d = FingerprintService.calculate_normalized_similarity(dist_d, bit_length=64)
            sim_p = FingerprintService.calculate_normalized_similarity(dist_p, bit_length=64)

            score = round((sim_a + sim_d + sim_p) / 3.0, 4)

            # Classify match based on configurable thresholds
            if score >= 0.95:
                classification = "Exact or near-exact perceptual match"
            elif score >= 0.85:
                classification = "High visual similarity"
            elif score >= 0.70:
                classification = "Partial or cropped similarity"
            else:
                classification = "Low similarity"

            return score, "pHash + aHash + dHash", dist_a, dist_d, dist_p, classification
        except Exception:
            return None, None, None, None, None, "Unable to verify"

    # ------------------------------------------------------------- Run Search
    def run_search(self, evidence_id: str) -> WebDiscoverySession:
        """
        Automatically run reverse image search, scrape candidate sources,
        and perform perceptual hash verification.
        """
        now_utc = datetime.now(timezone.utc).isoformat()
        session_id = self._generate_session_id()
        stored_results: List[WebDiscoveryResult] = []

        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        provider_name = str(getattr(self.provider, "PROVIDER_NAME", "Google Cloud Vision"))

        self.audit_logger.log_event(
            action="AUTOMATIC_REVERSE_SEARCH_STARTED",
            details={
                "session_id": session_id,
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "provider": provider_name,
            },
            actor="DigitalShield Automation Engine",
        )

        mime = evidence.mime_type or ""
        is_video = mime in VIDEO_MIMES
        is_image = mime in SUPPORTED_IMAGE_MIMES or mime.startswith("image/")

        video_note = None
        if is_video:
            video_note = (
                "Video evidence was submitted. DigitalShield's automatic web discovery currently performs "
                "image-based search only. Video frame extraction for reverse search is not yet implemented."
            )

        base_limitations = [
            "Reverse image search results depend on the external provider's indexed and accessible content. "
            "DigitalShield cannot guarantee discovery of every online occurrence. A missing result does not "
            "establish that an image has never been published online.",
            "Perceptual hash similarity is an investigative indicator and does not independently establish "
            "image identity, unauthorized distribution, or the identity of an uploader.",
            "Provider-reported matches are probabilistic indicators and are strictly distinguished from "
            "independently calculated perceptual hashes.",
        ]

        if is_video:
            base_limitations.append(video_note)
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=getattr(self.provider, "PROVIDER_NAME", "Google Cloud Vision"),
                started_at=now_utc,
                completed_at=now_utc,
                status="NO_RESULTS",
                error_message=video_note,
                is_video_evidence=True,
                video_search_note=video_note,
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            return session

        if not is_image:
            err_msg = f"Web image search is not supported for evidence of type '{mime}'."
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=getattr(self.provider, "PROVIDER_NAME", "Google Cloud Vision"),
                started_at=now_utc,
                completed_at=now_utc,
                status="FAILED",
                error_message=err_msg,
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            return session

        # Verify vault path
        vault_path = Path(evidence.stored_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Evidence vault file not found: '{evidence.stored_path}'")

        # Step 1: Call Provider
        self.audit_logger.log_event(
            action="REVERSE_SEARCH_PROVIDER_REQUESTED",
            details={
                "session_id": session_id,
                "evidence_id": evidence_id,
                "provider": provider_name,
            },
            actor="DigitalShield Web Discovery Service",
        )

        try:
            web_data = self.provider.search_web(vault_path)
        except CredentialError as ce:
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=datetime.now(timezone.utc).isoformat(),
                status="MISSING_CREDENTIALS",
                error_message=str(ce),
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            self.audit_logger.log_event(
                action="REVERSE_SEARCH_FAILED",
                details={
                    "case_id": evidence.case_id,
                    "session_id": session_id,
                    "evidence_id": evidence_id,
                    "error": "MISSING_CREDENTIALS",
                },
                actor="DigitalShield Web Discovery Service",
            )
            return session
        except Exception as e:
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=datetime.now(timezone.utc).isoformat(),
                status="FAILED",
                error_message=str(e),
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            self.audit_logger.log_event(
                action="REVERSE_SEARCH_FAILED",
                details={
                    "case_id": evidence.case_id,
                    "session_id": session_id,
                    "evidence_id": evidence_id,
                    "error": str(e)[:250],
                },
                actor="DigitalShield Web Discovery Service",
            )
            return session

        # Step 2: Collect candidate entries & deduplicate
        candidates: List[Dict[str, Any]] = []
        seen_norms: set = set()

        def _add(url: str, mtype: str, score=None, media_urls=None, title=None):
            norm = normalize_url(url)
            if norm not in seen_norms:
                seen_norms.add(norm)
                candidates.append({
                    "url": url,
                    "match_type": mtype,
                    "provider_score": score,
                    "media_urls": media_urls or [],
                    "title": title,
                })

        for url in web_data.get("full_matching_image_urls", []):
            _add(url, "EXACT_MATCH")
        for url in web_data.get("partial_matching_image_urls", []):
            _add(url, "PARTIAL_MATCH")
        for url in web_data.get("visually_similar_image_urls", []):
            _add(url, "VISUALLY_SIMILAR")
        for page in web_data.get("pages_with_matching_images", []):
            page_url = page.get("url", "")
            if page_url:
                media_urls = page.get("full_images", []) + page.get("partial_images", [])
                _add(
                    page_url,
                    "PAGE_WITH_IMAGE",
                    score=page.get("score"),
                    media_urls=media_urls,
                    title=page.get("page_title"),
                )

        verified_count = 0
        unverified_count = 0
        failed_count = 0

        # Step 3: Scrape public candidate pages & calculate perceptual hashes
        for entry in candidates:
            result_id = self._generate_result_id(stored_results)
            retrieval_ts = datetime.now(timezone.utc).isoformat()

            page_info = enrich_page(
                page_url=entry["url"],
                client=self.client,
                provided_title=entry.get("title"),
                provided_media_urls=entry.get("media_urls"),
            )

            scrape_status = "SUCCESS" if page_info.get("retrieval_status") == "RETRIEVED" else "FAILED"
            if scrape_status == "FAILED":
                failed_count += 1

            self.audit_logger.log_event(
                action="PUBLIC_SOURCE_SCRAPED",
                details={
                    "case_id": evidence.case_id,
                    "evidence_id": evidence_id,
                    "session_id": session_id,
                    "result_id": result_id,
                    "source_url": entry["url"],
                    "status": scrape_status,
                },
                actor="DigitalShield Scrapling Engine",
            )

            # Compare candidate media with evidence perceptual hashes
            target_media = page_info.get("media_url")
            ind_score, ind_method, dist_a, dist_d, dist_p, classification = None, None, None, None, None, "Unable to verify"

            if target_media:
                ind_score, ind_method, dist_a, dist_d, dist_p, classification = self._compare_remote_image(
                    target_media, evidence_id
                )
                if ind_score is not None:
                    verified_count += 1
                    self.audit_logger.log_event(
                        action="CANDIDATE_IMAGE_VERIFIED",
                        details={
                            "case_id": evidence.case_id,
                            "evidence_id": evidence_id,
                            "session_id": session_id,
                            "result_id": result_id,
                            "media_url": target_media,
                            "score": ind_score,
                            "classification": classification,
                        },
                        actor="DigitalShield Fingerprint Verifier",
                    )
                else:
                    unverified_count += 1
                    self.audit_logger.log_event(
                        action="CANDIDATE_IMAGE_UNVERIFIED",
                        details={
                            "case_id": evidence.case_id,
                            "evidence_id": evidence_id,
                            "session_id": session_id,
                            "result_id": result_id,
                            "media_url": target_media,
                        },
                        actor="DigitalShield Fingerprint Verifier",
                    )
            else:
                unverified_count += 1

            platform_name = detect_platform_name(entry["url"])

            wdr = WebDiscoveryResult(
                result_id=result_id,
                session_id=session_id,
                evidence_id=evidence_id,
                case_id=evidence.case_id,
                source_url=entry["url"],
                page_title=page_info.get("page_title"),
                domain=page_info.get("domain") or platform_name,
                platform=platform_name,
                media_url=target_media,
                canonical_url=page_info.get("canonical_url"),
                provider_match_type=entry["match_type"],
                provider_similarity=entry.get("provider_score"),
                provider_score=entry.get("provider_score"),
                ahash_distance=dist_a,
                dhash_distance=dist_d,
                phash_distance=dist_p,
                calculated_similarity=ind_score,
                independent_similarity_score=ind_score,
                independent_matching_method=ind_method,
                discovery_timestamp=retrieval_ts,
                retrieval_timestamp=retrieval_ts,
                scrape_status=scrape_status,
                retrieval_status=page_info.get("retrieval_status", "RETRIEVED"),
                verification_status=classification,
                status="Source discovered",
                notes=page_info.get("notes"),
                limitations=base_limitations,
            )
            stored_results.append(wdr)

            self.audit_logger.log_event(
                action="PUBLIC_SOURCE_DISCOVERED",
                details={
                    "session_id": session_id,
                    "result_id": result_id,
                    "source_url": entry["url"],
                    "platform": platform_name,
                    "classification": classification,
                },
                actor="DigitalShield Web Discovery Service",
            )

        completed_ts = datetime.now(timezone.utc).isoformat()
        session_status = "COMPLETED" if len(candidates) > 0 else "NO_RESULTS"

        session = WebDiscoverySession(
            session_id=session_id,
            case_id=evidence.case_id,
            evidence_id=evidence_id,
            provider=provider_name,
            started_at=now_utc,
            completed_at=completed_ts,
            status=session_status,
            total_results=len(stored_results),
            verified_matches=verified_count,
            unverified_results=unverified_count,
            failed_sources=failed_count,
            best_guess_labels=web_data.get("best_guess_labels", []),
            is_video_evidence=False,
            limitations=base_limitations,
        )

        self._persist_session(session, stored_results)

        self.audit_logger.log_event(
            action="REVERSE_SEARCH_COMPLETED",
            details={
                "session_id": session_id,
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "total_results": len(stored_results),
                "verified_matches": verified_count,
                "failed_sources": failed_count,
            },
            actor="DigitalShield Web Discovery Service",
        )

        return session

    def _persist_session(self, session: WebDiscoverySession, results: List[WebDiscoveryResult]) -> None:
        """Persist session and results to JSONStore and case analysis directory."""
        self.store.save_web_discovery_session(session.to_dict())

        case_dir = self.base_dir / "cases" / session.case_id / "analysis" / "web_discovery"
        case_dir.mkdir(parents=True, exist_ok=True)

        session_file = case_dir / f"session_{session.session_id}.json"
        with open(session_file, "w", encoding="utf-8") as f:
            json.dump(session.to_dict(), f, indent=2)

        for result in results:
            self.store.save_web_discovery_result(result.to_dict())
            result_file = case_dir / f"result_{result.result_id}.json"
            with open(result_file, "w", encoding="utf-8") as f:
                json.dump(result.to_dict(), f, indent=2)

    def get_session(self, session_id: str) -> Optional[WebDiscoverySession]:
        data = self.store.get_web_discovery_session(session_id)
        return WebDiscoverySession.from_dict(data) if data else None

    def list_sessions_by_evidence(self, evidence_id: str) -> List[WebDiscoverySession]:
        recs = self.store.list_web_discovery_sessions_by_evidence(evidence_id)
        return [WebDiscoverySession.from_dict(r) for r in recs]

    def list_results_by_session(self, session_id: str) -> List[WebDiscoveryResult]:
        recs = self.store.list_web_discovery_results_by_session(session_id)
        return [WebDiscoveryResult.from_dict(r) for r in recs]

    def list_results_by_case(self, case_id: str) -> List[WebDiscoveryResult]:
        recs = self.store.list_web_discovery_results_by_case(case_id)
        return [WebDiscoveryResult.from_dict(r) for r in recs]
