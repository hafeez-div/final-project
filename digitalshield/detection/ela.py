"""
Error Level Analysis (ELA) detection engine for DigitalShield.

FORENSIC INTEGRITY & ETHICAL RULES:
- NEVER modifies original or preserved evidence files.
- Operates strictly on read-only evidence vaults.
- Generates derived analysis data (ELA difference statistics).
- ELA is a probabilistic indicator and NOT definitive proof of image manipulation, authenticity, or forgery.
- Never infer authorship, ownership, or guilt based on ELA anomalies.
"""

import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from PIL import Image, ImageChops, ImageStat

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.detection.models import ELAResult, ELAStatistics
from digitalshield.security.audit import AuditLogger
from digitalshield.storage.json_store import JSONStore

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


class ELADetector:
    """
    Forensic engine performing Error Level Analysis (ELA) on preserved evidence images.
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

    def analyze_evidence(
        self,
        evidence_id: str,
        quality: int = 90,
        scale: int = 15,
        force_recompute: bool = False
    ) -> ELAResult:
        """
        Execute Error Level Analysis (ELA) on a preserved evidence item.
        Performs in-memory JPEG recompression against original image buffer and calculates
        error level statistics, anomaly scores, and probabilistic assessments.
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        if not self._is_image_evidence(evidence):
            raise ValueError(
                f"Unsupported evidence type '{evidence.mime_type}'. "
                f"ELA analysis is only supported for image evidence."
            )

        # Check existing result in store unless force_recompute is True
        if not force_recompute:
            cached = self.store.get_ela(evidence_id)
            if cached:
                return ELAResult.from_dict(cached)

        vault_path = Path(evidence.stored_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Preserved evidence file not found at '{evidence.stored_path}'.")

        # Process image in read-only mode
        try:
            with Image.open(vault_path) as orig_img:
                # Convert to RGB mode for standardized JPEG recompression comparison
                img_rgb = orig_img.convert("RGB")
                width, height = img_rgb.size

                # In-memory JPEG recompression buffer
                buf = io.BytesIO()
                img_rgb.save(buf, format="JPEG", quality=quality)
                buf.seek(0)

                with Image.open(buf) as recomp_img:
                    # Compute pixel-wise absolute difference
                    diff = ImageChops.difference(img_rgb, recomp_img)
                    diff_gray = diff.convert("L")
                    stat = ImageStat.Stat(diff_gray)

                    mean_err = round(float(stat.mean[0]), 4)
                    max_err = round(float(stat.extrema[0][1]), 4)
                    stddev_err = round(float(stat.stddev[0]), 4)
                    rms_err = round(float(stat.rms[0]), 4)

                    # Dynamic threshold for identifying high-error regions
                    high_thresh = max(12, int(mean_err + 1.5 * stddev_err))
                    high_mask = diff_gray.point(lambda p: 255 if p >= high_thresh else 0)
                    bbox = high_mask.getbbox()
                    bbox_list = list(bbox) if bbox else None

                    # Count high error pixels using histogram (clean, high performance)
                    hist = diff_gray.histogram()
                    high_error_pixels = sum(hist[high_thresh:])
                    total_pixels = width * height
                    high_error_ratio = round(high_error_pixels / float(total_pixels), 6)

        except Exception as e:
            raise ValueError(f"Failed to execute ELA processing on evidence: {e}")

        # Normalized anomaly score computation (0.0 to 1.0)
        norm_mean = min(1.0, mean_err / 25.0)
        norm_stddev = min(1.0, stddev_err / 20.0)
        norm_ratio = min(1.0, high_error_ratio * 4.0)
        anomaly_score = round(0.4 * norm_stddev + 0.3 * norm_mean + 0.3 * norm_ratio, 4)

        # Confidence based on image resolution
        if width >= 200 and height >= 200:
            confidence = 0.85
        elif width >= 100 and height >= 100:
            confidence = 0.80
        else:
            confidence = 0.70

        # Probabilistic assessment phrasing
        if anomaly_score < 0.25:
            assessment = (
                "Low ELA anomaly detected: Uniform compression error profile consistent across image surface "
                "(probabilistic assessment; derived forensic indicator)."
            )
        elif anomaly_score < 0.60:
            assessment = (
                "Moderate ELA variation detected: Minor localized error discrepancies observed; typical for "
                "high-contrast edges, text, or multiple JPEG saves (possible manipulation indicators; probabilistic assessment)."
            )
        else:
            assessment = (
                "High ELA anomaly detected: Significant localized error discrepancies and high variance observed across "
                "compression blocks (possible manipulation indicators; probabilistic assessment; derived forensic indicator)."
            )

        now_utc = datetime.now(timezone.utc).isoformat()

        ela_stats = ELAStatistics(
            mean_error=mean_err,
            max_error=max_err,
            stddev_error=stddev_err,
            rms_error=rms_err,
            high_error_pixels=high_error_pixels,
            high_error_ratio=high_error_ratio,
            high_error_bounding_box=bbox_list
        )

        result = ELAResult(
            evidence_id=evidence.evidence_id,
            case_id=evidence.case_id,
            original_filename=evidence.original_filename,
            analysis_timestamp=now_utc,
            image_width=width,
            image_height=height,
            color_mode="RGB",
            recompression_quality=quality,
            statistics=ela_stats,
            mean_error=mean_err,
            max_error=max_err,
            anomaly_score=anomaly_score,
            confidence=confidence,
            assessment=assessment,
            status="COMPLETED"
        )

        # 1. Persist in central JSON store
        self.store.save_ela(result.to_dict())

        # 2. Persist in case analysis directory (.digitalshield_data/cases/<case_id>/analysis/)
        case_analysis_dir = self.base_dir / "cases" / evidence.case_id / "analysis"
        case_analysis_dir.mkdir(parents=True, exist_ok=True)
        case_analysis_file = case_analysis_dir / f"ela_{evidence.evidence_id}.json"
        with open(case_analysis_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        # 3. Record audit log
        self.audit_logger.log_event(
            action="ELA_ANALYSIS_EXECUTED",
            details={
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "anomaly_score": anomaly_score,
                "mean_error": mean_err,
                "max_error": max_err,
                "quality": quality,
            },
            actor="DigitalShield ELA Engine"
        )

        return result

    def get_analysis(self, evidence_id: str) -> Optional[ELAResult]:
        """Retrieve stored ELA analysis by Evidence ID."""
        data = self.store.get_ela(evidence_id)
        if data:
            return ELAResult.from_dict(data)
        return None

    def list_analyses(self) -> List[ELAResult]:
        """List all stored ELA analysis results."""
        records = self.store.list_ela()
        return [ELAResult.from_dict(r) for r in records]
