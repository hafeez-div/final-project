"""
AI Deepfake and Synthetic Media Assessment module for DigitalShield.

FORENSIC INTEGRITY & ETHICAL RULES:
- NEVER modifies original or preserved evidence files. Operates strictly on read-only evidence vaults.
- Uses derived analysis data (heuristics, statistics, perceptual features).
- Produces PROBABILISTIC assessments with explicit confidence intervals and limitations.
- NEVER claims definitive proof of forgery, authenticity, authorship, or identity.
- Clearly distinguishes between heuristic baselines and trained machine learning models.
"""

import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image, ImageChops, ImageStat

from digitalshield.detection.interfaces import BaseDeepfakeDetector
from digitalshield.detection.models import DeepfakeAnalysisResult, DetectorType
from digitalshield.evidence.manager import EvidenceManager
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

COMMON_GENERATIVE_RESOLUTIONS = {
    (256, 256),
    (512, 512),
    (768, 768),
    (1024, 1024),
    (512, 768),
    (768, 512),
    (1024, 768),
    (768, 1024),
}


class BaselineDeepfakeDetector(BaseDeepfakeDetector):
    """
    Safe heuristic baseline detector evaluating synthetic media indicators.
    Uses multi-feature heuristics (resolution, metadata presence, localized compression,
    and channel distribution) to generate a deterministic, transparent assessment.

    NOTE: This is a clearly designated heuristic baseline, not a trained neural network.
    """

    @property
    def name(self) -> str:
        return "DigitalShield Heuristic Baseline v1.0"

    @property
    def detector_type(self) -> DetectorType:
        return DetectorType.HEURISTIC_BASELINE

    def analyze(
        self,
        evidence_path: Path,
        evidence_metadata: Dict[str, Any],
        derived_features: Optional[Dict[str, Any]] = None
    ) -> DeepfakeAnalysisResult:
        """
        Perform heuristic synthetic content assessment on a preserved image.
        """
        evidence_id = evidence_metadata.get("evidence_id", "UNKNOWN")
        case_id = evidence_metadata.get("case_id", "UNKNOWN")
        original_filename = evidence_metadata.get("original_filename")

        indicators: List[str] = []
        features_used: List[str] = [
            "Image resolution & aspect ratio analysis",
            "Metadata / EXIF presence verification",
            "In-memory compression & error variance inspection",
            "RGB channel statistics & dynamic range distribution",
        ]

        prob_score = 0.20  # Neutral baseline prior

        # 1. Open read-only image buffer
        with Image.open(evidence_path) as orig_img:
            width, height = orig_img.size
            mode = orig_img.mode
            img_rgb = orig_img.convert("RGB")

            # Check EXIF info presence
            has_exif = False
            try:
                exif_data = orig_img.getexif()
                if exif_data and len(exif_data) > 0:
                    has_exif = True
            except Exception:
                has_exif = False

            if has_exif:
                indicators.append("Standard camera EXIF metadata detected (consistent with physical capture devices).")
                prob_score -= 0.10
            else:
                indicators.append("Absence of hardware EXIF camera tags (common in generated, stripped, or web-transcoded media).")
                prob_score += 0.15

            # 2. Check resolution & aspect ratio characteristics
            if (width, height) in COMMON_GENERATIVE_RESOLUTIONS:
                indicators.append(
                    f"Dimensions ({width}x{height}) match common generative AI model default output resolutions."
                )
                prob_score += 0.20
            elif width == height:
                indicators.append(f"Square aspect ratio ({width}x{height}) observed.")
                prob_score += 0.05
            else:
                indicators.append(f"Standard non-square aspect ratio ({width}x{height}) observed.")

            # 3. Channel variance and color distribution
            stat = ImageStat.Stat(img_rgb)
            mean_vals = stat.mean
            stddev_vals = stat.stddev
            avg_stddev = sum(stddev_vals) / len(stddev_vals)

            if avg_stddev < 20.0:
                indicators.append("Low color channel variance / high uniformity across image surface.")
                prob_score += 0.10
            else:
                indicators.append(f"Normal color channel standard deviation across RGB ({avg_stddev:.2f}).")

            # 4. In-memory compression error level analysis check
            buf = io.BytesIO()
            img_rgb.save(buf, format="JPEG", quality=90)
            buf.seek(0)
            with Image.open(buf) as recomp_img:
                diff = ImageChops.difference(img_rgb, recomp_img)
                diff_stat = ImageStat.Stat(diff.convert("L"))
                diff_mean = diff_stat.mean[0]
                diff_stddev = diff_stat.stddev[0]

                if diff_stddev > 15.0:
                    indicators.append(
                        f"High localized compression variance detected in recompression diff (stddev: {diff_stddev:.2f})."
                    )
                    prob_score += 0.15
                else:
                    indicators.append(
                        f"Uniform compression error characteristics (stddev: {diff_stddev:.2f})."
                    )

        # Bound probability strictly between 0.0 and 1.0
        synthetic_probability = round(max(0.05, min(0.95, prob_score)), 4)

        # Confidence calculation based on resolution and signal quality
        if width >= 256 and height >= 256:
            confidence = 0.75
        elif width >= 100 and height >= 100:
            confidence = 0.65
        else:
            confidence = 0.50

        # Probabilistic assessment phrasing
        if synthetic_probability < 0.35:
            assessment = (
                "Low synthetic probability: Technical features and metadata consistency align with conventional "
                "digital media (probabilistic assessment; heuristic baseline)."
            )
        elif synthetic_probability < 0.60:
            assessment = (
                "Moderate / inconclusive synthetic indicators: Mixed technical signals observed across resolution "
                "and compression profiles (possible manipulation indicators; probabilistic assessment; heuristic baseline)."
            )
        else:
            assessment = (
                "Elevated synthetic indicators: Observed dimension and compression patterns suggest possible synthetic "
                "or heavily processed content (possible synthetic content; probabilistic assessment; heuristic baseline)."
            )

        limitations = [
            "The baseline detector is a heuristic rule-based evaluator and NOT a validated forensic deepfake detector.",
            "Real-world deployment requires representative training data, formal validation datasets, false-positive/false-negative calibration, and independent forensic benchmarking.",
            "Assessments are strictly probabilistic indicators and must never be interpreted as definitive proof of authenticity, manipulation, or synthetic fabrication.",
            "Never infer identity, authorship, ownership, or criminal responsibility based on these assessment metrics.",
        ]

        now_utc = datetime.now(timezone.utc).isoformat()

        return DeepfakeAnalysisResult(
            evidence_id=evidence_id,
            case_id=case_id,
            original_filename=original_filename,
            analysis_timestamp=now_utc,
            detector_name=self.name,
            detector_type=self.detector_type,
            synthetic_probability=synthetic_probability,
            confidence=confidence,
            assessment=assessment,
            indicators=indicators,
            limitations=limitations,
            features_used=features_used,
            status="COMPLETED"
        )


class DeepfakeAssessmentService:
    """
    Forensic orchestration service managing deepfake and synthetic media assessments.
    Enforces evidence immutability, storage persistence, and append-only audit logging.
    """

    def __init__(self, base_dir: Optional[Path] = None, detector: Optional[BaseDeepfakeDetector] = None):
        if base_dir is None:
            env_dir = os.environ.get("DIGITALSHIELD_DATA_DIR")
            base_dir = Path(env_dir) if env_dir else Path(".digitalshield_data")
        self.base_dir = Path(base_dir)
        self.evidence_manager = EvidenceManager(self.base_dir)
        self.store = JSONStore(self.base_dir)
        self.audit_logger = AuditLogger(self.base_dir / "audit.log")
        self.detector = detector if detector is not None else BaselineDeepfakeDetector()

    def _is_image_evidence(self, evidence) -> bool:
        """Verify if evidence item is a supported image format."""
        if evidence.mime_type and evidence.mime_type.lower() in SUPPORTED_IMAGE_MIMES:
            return True
        ext = Path(evidence.original_filename).suffix.lower()
        if ext in SUPPORTED_IMAGE_EXTENSIONS:
            return True
        return False

    def assess_evidence(
        self,
        evidence_id: str,
        force_recompute: bool = False
    ) -> DeepfakeAnalysisResult:
        """
        Execute deepfake assessment on a preserved evidence item.
        """
        evidence = self.evidence_manager.get_evidence(evidence_id)
        if not evidence:
            raise ValueError(f"Evidence ID '{evidence_id}' does not exist.")

        if not self._is_image_evidence(evidence):
            raise ValueError(
                f"Unsupported evidence type '{evidence.mime_type}'. "
                f"Deepfake assessment is only supported for image evidence."
            )

        if not force_recompute:
            cached = self.store.get_deepfake(evidence_id)
            if cached:
                return DeepfakeAnalysisResult.from_dict(cached)

        vault_path = Path(evidence.stored_path)
        if not vault_path.exists():
            raise FileNotFoundError(f"Preserved evidence file not found at '{evidence.stored_path}'.")

        # Execute analysis using configured detector
        metadata_dict = {
            "evidence_id": evidence.evidence_id,
            "case_id": evidence.case_id,
            "original_filename": evidence.original_filename,
        }

        result = self.detector.analyze(
            evidence_path=vault_path,
            evidence_metadata=metadata_dict
        )

        # 1. Persist in central JSONStore
        self.store.save_deepfake(result.to_dict())

        # 2. Persist in case analysis folder (.digitalshield_data/cases/<case_id>/analysis/)
        case_analysis_dir = self.base_dir / "cases" / evidence.case_id / "analysis"
        case_analysis_dir.mkdir(parents=True, exist_ok=True)
        case_analysis_file = case_analysis_dir / f"deepfake_{evidence.evidence_id}.json"
        with open(case_analysis_file, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

        # 3. Append to audit log
        self.audit_logger.log_event(
            action="DEEPFAKE_ASSESSMENT_EXECUTED",
            details={
                "evidence_id": evidence.evidence_id,
                "case_id": evidence.case_id,
                "detector_name": result.detector_name,
                "detector_type": result.detector_type.value,
                "synthetic_probability": result.synthetic_probability,
                "confidence": result.confidence,
            },
            actor="DigitalShield Deepfake Engine"
        )

        return result

    def get_assessment(self, evidence_id: str) -> Optional[DeepfakeAnalysisResult]:
        """Retrieve stored deepfake assessment by Evidence ID."""
        data = self.store.get_deepfake(evidence_id)
        if data:
            return DeepfakeAnalysisResult.from_dict(data)
        return None

    def list_assessments(self) -> List[DeepfakeAnalysisResult]:
        """List all stored deepfake assessment records."""
        records = self.store.list_deepfake()
        return [DeepfakeAnalysisResult.from_dict(r) for r in records]
