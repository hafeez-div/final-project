"""
Automatic Web Discovery & Reverse Image Search Service for DigitalShield.

Performs:
1. Automated provider execution (Google Lens Reverse Image Discovery) using read-only evidence.
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
from digitalshield.web_discovery.google_lens_provider import (
    GoogleLensProvider,
    ReverseSearchProviderError,
)
from digitalshield.web_discovery.lens_models import detect_platform_name
from digitalshield.web_discovery.models import WebDiscoveryResult, WebDiscoverySession
from digitalshield.web_discovery.page_enricher import deduplicate_urls, enrich_page, normalize_url
from digitalshield.web_discovery.providers.base_provider import BaseReverseImageProvider

# Provider error alias
ProviderError = ReverseSearchProviderError
CredentialError = ReverseSearchProviderError

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
        self.provider = provider if provider is not None else GoogleLensProvider()
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
    @staticmethod
    def _result_status(match_type: str, score: Optional[float] = None) -> str:
        if match_type in ("EXACT_MATCH", "PARTIAL_MATCH"):
            return "Source discovered"
        if match_type == "VISUALLY_SIMILAR":
            return "Potential media match"
        return "Awaiting investigator review"

    def _compare_remote_image(
        self, media_url: str, evidence_id: str
    ) -> Tuple[Optional[float], Optional[str], Optional[int], Optional[int], Optional[int], str]:
        """
        Download a remote candidate image and compare it against evidence perceptual hashes.
        Uses multi-strategy evaluation (Standard multi-hash, Aspect-normalized center crop for thumbnails).
        NEVER modifies the original evidence file.

        Returns:
            (similarity_score, method, dist_a, dist_d, dist_p, classification)
        """
        try:
            validated = self.client.validate_url(media_url)
            status, _hdrs, media_bytes = self.client.fetch_public_url(validated)
            if status >= 400 or not media_bytes:
                return None, None, None, None, None, "Unable to verify"

            # Compute public image hashes
            with Image.open(io.BytesIO(media_bytes)) as pub_img_raw:
                pub_img = pub_img_raw.convert("RGB")
                pub_w, pub_h = pub_img.size
                pub_a = str(imagehash.average_hash(pub_img))
                pub_d = str(imagehash.dhash(pub_img))
                pub_p = str(imagehash.phash(pub_img))

            # Strategy 1: Standard baseline hashes against evidence vault item
            ev_fp = self.fingerprint_service.generate_fingerprints(evidence_id)
            dist_a = FingerprintService.calculate_hamming_distance(pub_a, ev_fp.ahash)
            dist_d = FingerprintService.calculate_hamming_distance(pub_d, ev_fp.dhash)
            dist_p = FingerprintService.calculate_hamming_distance(pub_p, ev_fp.phash)

            sim_a = FingerprintService.calculate_normalized_similarity(dist_a, bit_length=64)
            sim_d = FingerprintService.calculate_normalized_similarity(dist_d, bit_length=64)
            sim_p = FingerprintService.calculate_normalized_similarity(dist_p, bit_length=64)

            best_score = round((sim_a + sim_d + sim_p) / 3.0, 4)
            best_method = "Standard multi-hash (pHash + aHash + dHash)"
            best_dist_a, best_dist_d, best_dist_p = dist_a, dist_d, dist_p

            # Strategy 2: Aspect-ratio normalized center crop for thumbnails/crops
            # Read-only access to evidence vault
            evidence = self.evidence_manager.get_evidence(evidence_id)
            if evidence and evidence.stored_path:
                ev_path = Path(evidence.stored_path)
                if ev_path.exists():
                    with Image.open(ev_path) as ev_img_raw:
                        ev_img = ev_img_raw.convert("RGB")
                        ev_w, ev_h = ev_img.size

                        pub_aspect = pub_w / max(pub_h, 1)
                        ev_aspect = ev_w / max(ev_h, 1)

                        if abs(pub_aspect - ev_aspect) > 0.08:
                            if ev_aspect > pub_aspect:
                                # Evidence is wider: center-crop width
                                crop_w = int(ev_h * pub_aspect)
                                left = max(0, (ev_w - crop_w) // 2)
                                crop_box = (left, 0, left + crop_w, ev_h)
                            else:
                                # Evidence is taller: center-crop height
                                crop_h = int(ev_w / pub_aspect)
                                top = max(0, (ev_h - crop_h) // 2)
                                crop_box = (0, top, ev_w, top + crop_h)

                            cropped_ev = ev_img.crop(crop_box)
                            c_a = str(imagehash.average_hash(cropped_ev))
                            c_d = str(imagehash.dhash(cropped_ev))
                            c_p = str(imagehash.phash(cropped_ev))

                            cd_a = FingerprintService.calculate_hamming_distance(pub_a, c_a)
                            cd_d = FingerprintService.calculate_hamming_distance(pub_d, c_d)
                            cd_p = FingerprintService.calculate_hamming_distance(pub_p, c_p)

                            cs_a = FingerprintService.calculate_normalized_similarity(cd_a, bit_length=64)
                            cs_d = FingerprintService.calculate_normalized_similarity(cd_d, bit_length=64)
                            cs_p = FingerprintService.calculate_normalized_similarity(cd_p, bit_length=64)
                            crop_score = round((cs_a + cs_d + cs_p) / 3.0, 4)

                            if crop_score > best_score:
                                best_score = crop_score
                                best_method = "Aspect-normalized center crop"
                                best_dist_a, best_dist_d, best_dist_p = cd_a, cd_d, cd_p

            # Classify match based on required classification labels
            if best_score >= 0.95:
                classification = "Exact or near-exact visual match"
            elif best_score >= 0.85:
                classification = "High visual similarity"
            elif best_score >= 0.70:
                classification = "Partial visual similarity"
            else:
                classification = "Low similarity"

            return best_score, best_method, best_dist_a, best_dist_d, best_dist_p, classification
        except Exception:
            return None, None, None, None, None, "Unable to verify"

    # ------------------------------------------------------------- Run Search
    def run_search(self, evidence_id: str) -> WebDiscoverySession:
        """
        Automatically run reverse image search, scrape candidate sources,
        and perform perceptual hash verification.
        """
        start_dt = datetime.now(timezone.utc)
        now_utc = start_dt.isoformat()
        session_id = self._generate_session_id()
        stored_results: List[WebDiscoveryResult] = []

        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        provider_name = str(getattr(self.provider, "PROVIDER_NAME", "Google Lens"))

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
        self.audit_logger.log_event(
            action="WEB_DISCOVERY_SESSION_STARTED",
            details={"session_id": session_id, "evidence_id": evidence_id, "case_id": evidence.case_id},
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
            "Google Lens does not provide an official standalone public developer API; automated discovery "
            "operates via compliant search gateways. DigitalShield cannot guarantee discovery of every online "
            "occurrence. A missing result does not establish that an image has never been published online.",
            "Perceptual hash similarity is an investigative indicator and does not independently establish "
            "image identity, unauthorized distribution, or the identity of an uploader.",
            "Provider-reported matches are distinguished from independently calculated perceptual hashes.",
        ]

        if is_video:
            end_dt = datetime.now(timezone.utc)
            duration = round((end_dt - start_dt).total_seconds(), 3)
            base_limitations.append(video_note)
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=end_dt.isoformat(),
                search_duration_seconds=duration,
                image_submission_status="NOT_SUBMITTED_VIDEO",
                status="NO_RESULTS",
                error_message=video_note,
                is_video_evidence=True,
                video_search_note=video_note,
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            return session

        if not is_image:
            end_dt = datetime.now(timezone.utc)
            duration = round((end_dt - start_dt).total_seconds(), 3)
            err_msg = f"Web image search is not supported for evidence of type '{mime}'."
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=end_dt.isoformat(),
                search_duration_seconds=duration,
                image_submission_status="NOT_SUBMITTED_INVALID_FORMAT",
                status="INVALID_IMAGE",
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
        except ReverseSearchProviderError as pe:
            end_dt = datetime.now(timezone.utc)
            duration = round((end_dt - start_dt).total_seconds(), 3)
            err_str = str(pe)
            err_lower = err_str.lower()

            if "not configured" in err_lower or "missing" in err_lower or "credential" in err_lower or ("gateway" in err_lower and "key" in err_lower):
                sess_status = "PROVIDER_UNAVAILABLE"
                sub_status = "NOT_SUBMITTED_NO_GATEWAY"
                audit_act = "WEB_DISCOVERY_CREDENTIAL_ERROR"
            elif "rate limit" in err_lower or "blocked" in err_lower or "429" in err_lower:
                sess_status = "BLOCKED"
                sub_status = "SUBMISSION_BLOCKED"
                audit_act = "WEB_DISCOVERY_BLOCKED"
            elif "malformed" in err_lower or "parse" in err_lower:
                sess_status = "PARSE_ERROR"
                sub_status = "SUBMISSION_FAILED"
                audit_act = "WEB_DISCOVERY_PARSE_ERROR"
            elif "upload" in err_lower:
                sess_status = "FAILED"
                sub_status = "UPLOAD_FAILED"
                audit_act = "WEB_DISCOVERY_FAILED"
            elif "search" in err_lower:
                sess_status = "FAILED"
                sub_status = "SEARCH_FAILED"
                audit_act = "WEB_DISCOVERY_FAILED"
            else:
                sess_status = "FAILED"
                sub_status = "SUBMISSION_FAILED"
                audit_act = "WEB_DISCOVERY_FAILED"

            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=end_dt.isoformat(),
                search_duration_seconds=duration,
                image_submission_status=sub_status,
                status=sess_status,
                error_message=err_str,
                limitations=base_limitations,
            )
            self._persist_session(session, stored_results)
            self.audit_logger.log_event(
                action="REVERSE_SEARCH_FAILED",
                details={
                    "case_id": evidence.case_id,
                    "session_id": session_id,
                    "evidence_id": evidence_id,
                    "status": sess_status,
                    "error": err_str[:250],
                },
                actor="DigitalShield Web Discovery Service",
            )
            self.audit_logger.log_event(
                action=audit_act,
                details={
                    "case_id": evidence.case_id,
                    "session_id": session_id,
                    "evidence_id": evidence_id,
                    "error": err_str[:250],
                },
                actor="DigitalShield Web Discovery Service",
            )
            return session
        except Exception as e:
            end_dt = datetime.now(timezone.utc)
            duration = round((end_dt - start_dt).total_seconds(), 3)
            session = WebDiscoverySession(
                session_id=session_id,
                case_id=evidence.case_id,
                evidence_id=evidence_id,
                provider=provider_name,
                started_at=now_utc,
                completed_at=end_dt.isoformat(),
                search_duration_seconds=duration,
                image_submission_status="SUBMISSION_FAILED",
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
        exact_count = 0
        high_count = 0
        partial_count = 0
        unverified_count = 0
        failed_count = 0
        candidate_images_seen = set()

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
                candidate_images_seen.add(target_media)
                ind_score, ind_method, dist_a, dist_d, dist_p, classification = self._compare_remote_image(
                    target_media, evidence_id
                )
                if ind_score is not None:
                    verified_count += 1
                    if classification == "Exact or near-exact visual match":
                        exact_count += 1
                    elif classification == "High visual similarity":
                        high_count += 1
                    elif classification == "Partial visual similarity":
                        partial_count += 1

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
                publication_timestamp=page_info.get("publication_timestamp"),
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

        completed_dt = datetime.now(timezone.utc)
        completed_ts = completed_dt.isoformat()
        duration = round((completed_dt - start_dt).total_seconds(), 3)
        session_status = "COMPLETED" if len(candidates) > 0 else "NO_RESULTS"

        session = WebDiscoverySession(
            session_id=session_id,
            case_id=evidence.case_id,
            evidence_id=evidence_id,
            provider=provider_name,
            started_at=now_utc,
            completed_at=completed_ts,
            search_duration_seconds=duration,
            image_submission_status="SUBMITTED_AND_SEARCHED",
            status=session_status,
            total_results=len(stored_results),
            candidate_images_count=len(candidate_images_seen),
            verified_matches=verified_count,
            exact_matches=exact_count,
            high_similarity_matches=high_count,
            partial_matches=partial_count,
            unverified_results=unverified_count,
            failed_sources=failed_count,
            best_guess_labels=web_data.get("best_guess_labels", []),
            is_video_evidence=False,
            limitations=base_limitations,
        )

        self._persist_session(session, stored_results)

        self.audit_logger.log_event(
            action="WEB_DISCOVERY_COMPLETED",
            details={"session_id": session_id, "evidence_id": evidence_id, "case_id": evidence.case_id},
            actor="DigitalShield Web Discovery Service",
        )
        self.audit_logger.log_event(
            action="REVERSE_SEARCH_COMPLETED",
            details={
                "session_id": session_id,
                "evidence_id": evidence_id,
                "case_id": evidence.case_id,
                "total_results": len(stored_results),
                "verified_matches": verified_count,
                "exact_matches": exact_count,
                "high_similarity_matches": high_count,
                "partial_matches": partial_count,
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
