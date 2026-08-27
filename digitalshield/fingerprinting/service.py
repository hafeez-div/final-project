"""
FingerprintService: Modular perceptual hashing and similarity comparison engine for DigitalShield.

FORENSIC INTEGRITY & ETHICAL RULES:
- NEVER modifies original or preserved evidence files.
- Operates strictly on read-only evidence vaults.
- Generates derived analysis data (aHash, dHash, pHash).
- Perceptual similarity is probabilistic; never claim forensic certainty of identity, source, or authenticity.
"""

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
import imagehash
from PIL import Image

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.models import (
    AlgorithmFingerprint,
    ComparisonMetric,
    ComparisonResult,
    FingerprintResult,
)
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore

# Supported image MIME types for perceptual hashing
SUPPORTED_IMAGE_MIMES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "image/bmp",
    "image/tiff",
}

SUPPORTED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".gif",
    ".bmp",
    ".tiff",
}


class FingerprintService:
    """
    Service coordinating perceptual fingerprint generation, persistence, and similarity comparison.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")

    def _is_image_evidence(self, evidence) -> bool:
        """Check if an evidence item is a supported image format."""
        if evidence.mime_type and evidence.mime_type.lower() in SUPPORTED_IMAGE_MIMES:
            return True
        ext = Path(evidence.original_filename).suffix.lower()
        if ext in SUPPORTED_IMAGE_EXTENSIONS:
            return True
        return False

    def generate_fingerprints(
        self,
        evidence_id: str,
        force_recompute: bool = False
    ) -> FingerprintResult:
        """
        Extract perceptual fingerprints (aHash, dHash, pHash) from a preserved evidence image.
        Persists results to the JSON store as derived forensic analysis.
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        if not self._is_image_evidence(evidence):
            raise ValueError(
                f"Unsupported evidence type '{evidence.mime_type}'. "
                f"Perceptual fingerprinting is only supported for image evidence."
            )

        # Check existing fingerprints in store unless force_recompute is True
        if not force_recompute:
            cached = self.store.get_fingerprints(evidence_id)
            if cached:
                return FingerprintResult.from_dict(cached)

        vault_path = Path(evidence.stored_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Preserved evidence file not found at '{evidence.stored_path}'.")

        # Process image in read-only mode
        try:
            with Image.open(vault_path) as img:
                # Compute hashes (8x8 -> 64-bit standard perceptual hashes)
                ahash_obj = imagehash.average_hash(img)
                dhash_obj = imagehash.dhash(img)
                phash_obj = imagehash.phash(img)

                ahash_str = str(ahash_obj)
                dhash_str = str(dhash_obj)
                phash_str = str(phash_obj)
        except Exception as e:
            raise ValueError(f"Failed to process image for fingerprinting: {e}")

        now_utc = datetime.now(timezone.utc).isoformat()

        algorithms_map = {
            "aHash": AlgorithmFingerprint(
                algorithm="aHash",
                hash_value=ahash_str,
                bit_length=64
            ),
            "dHash": AlgorithmFingerprint(
                algorithm="dHash",
                hash_value=dhash_str,
                bit_length=64
            ),
            "pHash": AlgorithmFingerprint(
                algorithm="pHash",
                hash_value=phash_str,
                bit_length=64
            ),
        }

        result = FingerprintResult(
            evidence_id=evidence.evidence_id,
            case_id=evidence.case_id,
            original_filename=evidence.original_filename,
            generation_timestamp=now_utc,
            ahash=ahash_str,
            dhash=dhash_str,
            phash=phash_str,
            algorithms=algorithms_map,
            status="COMPLETED"
        )

        # Persist as derived analysis
        self.store.save_fingerprints(result.to_dict())

        # Record audit log
        self.audit_logger.log_event(
            action="FINGERPRINTS_GENERATED",
            details={
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "original_filename": evidence.original_filename,
                "ahash": ahash_str,
                "dhash": dhash_str,
                "phash": phash_str,
            },
            actor="DigitalShield Fingerprint Engine"
        )

        return result

    def get_fingerprints(self, evidence_id: str) -> Optional[FingerprintResult]:
        """Retrieve stored perceptual fingerprints for an evidence item."""
        data = self.store.get_fingerprints(evidence_id)
        if data:
            return FingerprintResult.from_dict(data)
        return None

    def list_fingerprints(self) -> List[FingerprintResult]:
        """List all stored perceptual fingerprint records."""
        records = self.store.list_fingerprints()
        return [FingerprintResult.from_dict(r) for r in records]

    @staticmethod
    def calculate_hamming_distance(hash_hex_a: str, hash_hex_b: str) -> int:
        """
        Calculate bit-level Hamming distance between two hex-encoded perceptual hashes.
        """
        hash_a = imagehash.hex_to_hash(hash_hex_a)
        hash_b = imagehash.hex_to_hash(hash_hex_b)
        return int(hash_a - hash_b)

    @staticmethod
    def calculate_normalized_similarity(hamming_distance: int, bit_length: int = 64) -> float:
        """
        Calculate normalized similarity score between 0.0 and 1.0.
        1.0 indicates identical perceptual hash (0 differing bits).
        0.0 indicates completely inverted hash (64 differing bits).
        """
        if bit_length <= 0:
            return 0.0
        score = 1.0 - (hamming_distance / float(bit_length))
        return max(0.0, min(1.0, round(score, 4)))

    def compare_fingerprints(
        self,
        evidence_id_a: str,
        evidence_id_b: str
    ) -> ComparisonResult:
        """
        Compare perceptual fingerprints between two evidence items.
        Computes Hamming distances and normalized similarity for aHash, dHash, and pHash.
        Provides a probabilistic overall assessment.
        """
        fp_a = self.generate_fingerprints(evidence_id_a)
        fp_b = self.generate_fingerprints(evidence_id_b)

        # Compute metrics for each algorithm
        algorithms = [
            ("aHash", fp_a.ahash, fp_b.ahash),
            ("dHash", fp_a.dhash, fp_b.dhash),
            ("pHash", fp_a.phash, fp_b.phash),
        ]

        metrics: Dict[str, ComparisonMetric] = {}
        similarity_sum = 0.0

        for algo_name, hash_a, hash_b in algorithms:
            dist = self.calculate_hamming_distance(hash_a, hash_b)
            norm_sim = self.calculate_normalized_similarity(dist, bit_length=64)
            metrics[algo_name] = ComparisonMetric(
                algorithm=algo_name,
                hash_a=hash_a,
                hash_b=hash_b,
                hamming_distance=dist,
                max_distance=64,
                normalized_similarity=norm_sim
            )
            similarity_sum += norm_sim

        overall_sim = round(similarity_sum / len(algorithms), 4)

        # Probabilistic assessment string
        if overall_sim == 1.0:
            assessment = "Identical perceptual hashes (Probabilistic indicator: Visually identical images under standard resolution)"
        elif overall_sim >= 0.90:
            assessment = "High perceptual similarity (Probabilistic indicator: Minor compression, resizing, or subtle edits)"
        elif overall_sim >= 0.75:
            assessment = "Moderate perceptual similarity (Probabilistic indicator: Noticeable alterations, cropping, or distinct visual variation)"
        else:
            assessment = "Low perceptual similarity (Probabilistic indicator: Visually distinct media assets)"

        now_utc = datetime.now(timezone.utc).isoformat()

        result = ComparisonResult(
            evidence_id_a=evidence_id_a,
            evidence_id_b=evidence_id_b,
            filename_a=fp_a.original_filename,
            filename_b=fp_b.original_filename,
            comparison_timestamp=now_utc,
            metrics=metrics,
            overall_similarity=overall_sim,
            assessment=assessment
        )

        # Audit logging
        self.audit_logger.log_event(
            action="FINGERPRINTS_COMPARED",
            details={
                "evidence_id_a": evidence_id_a,
                "evidence_id_b": evidence_id_b,
                "overall_similarity": overall_sim,
                "ahash_distance": metrics["aHash"].hamming_distance,
                "dhash_distance": metrics["dHash"].hamming_distance,
                "phash_distance": metrics["pHash"].hamming_distance,
            },
            actor="DigitalShield Fingerprint Engine"
        )

        return result
