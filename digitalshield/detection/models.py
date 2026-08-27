"""
Data models for DigitalShield Image Manipulation Detection and Error Level Analysis (ELA).

FORENSIC INTEGRITY RULES:
- ELA results are derived analysis artifacts, NEVER original evidence.
- ELA is a probabilistic indicator and NOT definitive proof of image manipulation, authenticity, or forgery.
- Never infer who created, modified, or owns the image based on ELA anomalies.
"""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ELAStatistics(BaseModel):
    """
    Detailed statistical metrics computed from Error Level Analysis difference maps.
    """
    mean_error: float = Field(description="Mean pixel error level across the image")
    max_error: float = Field(description="Maximum observed error level in difference map")
    stddev_error: float = Field(description="Standard deviation of error levels")
    rms_error: float = Field(description="Root mean square error level")
    high_error_pixels: int = Field(description="Count of pixels exceeding the high-error threshold")
    high_error_ratio: float = Field(description="Ratio of high-error pixels to total image pixels")
    high_error_bounding_box: Optional[List[int]] = Field(
        default=None,
        description="Bounding box [left, top, right, bottom] enclosing high-error regions, if present"
    )


class ELAResult(BaseModel):
    """
    Structured forensic result for Error Level Analysis (ELA) on an evidence image.
    """
    evidence_id: str = Field(description="Associated Evidence ID (e.g. EVD-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    original_filename: Optional[str] = Field(default=None, description="Original filename of the evidence")
    analysis_timestamp: str = Field(description="ISO 8601 UTC timestamp of analysis execution")
    
    image_width: int = Field(description="Image width in pixels")
    image_height: int = Field(description="Image height in pixels")
    color_mode: str = Field(description="Color mode analyzed (e.g. RGB)")
    recompression_quality: int = Field(default=90, description="JPEG quality level used for recompression comparison")
    
    statistics: ELAStatistics = Field(description="Detailed statistical breakdown of ELA difference map")
    mean_error: float = Field(description="Mean error level")
    max_error: float = Field(description="Maximum error level")
    
    anomaly_score: float = Field(
        description="Normalized anomaly score between 0.0 (uniform) and 1.0 (high localized variance)"
    )
    confidence: float = Field(
        description="Confidence score in the ELA assessment based on resolution and signal quality"
    )
    assessment: str = Field(
        description="Probabilistic assessment of potential manipulation indicators"
    )
    disclaimer: str = Field(
        default=(
            "Error Level Analysis (ELA) is a probabilistic derived forensic indicator and is NOT "
            "definitive proof of image manipulation, authenticity, or forgery. Natural texture variations, "
            "sharp edges, and legitimate resaving can produce error level anomalies. Never infer authorship or ownership."
        ),
        description="Forensic limitations and ethics disclaimer"
    )
    status: str = Field(default="COMPLETED", description="Status of the ELA detection run")

    def to_dict(self) -> dict:
        """Convert ELAResult to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "ELAResult":
        """Construct ELAResult from dictionary."""
        return cls(**data)


class DetectorType(str, Enum):
    """
    Classification of deepfake assessment detectors.
    Ensures complete transparency regarding whether an analysis originates from
    a heuristic baseline or an actual machine learning model.
    """
    HEURISTIC_BASELINE = "heuristic baseline"
    TRAINED_MODEL = "trained model"
    PRETRAINED_MODEL = "pretrained model"


class DeepfakeAnalysisResult(BaseModel):
    """
    Structured forensic result for AI-based deepfake / synthetic media assessment.

    FORENSIC INTEGRITY RULES:
    - This is a probabilistic assessment, NEVER definitive proof of forgery.
    - Never infer identity, authorship, ownership, or criminal responsibility.
    - Result is stored as derived analysis metadata, preserving original evidence immutability.
    """
    evidence_id: str = Field(description="Associated Evidence ID (e.g. EVD-2026-000001)")
    case_id: str = Field(description="Associated Case ID (e.g. DS-2026-000001)")
    original_filename: Optional[str] = Field(default=None, description="Original filename of the evidence")
    analysis_timestamp: str = Field(description="ISO 8601 UTC timestamp of assessment execution")

    detector_name: str = Field(description="Name/identifier of detector implementation used")
    detector_type: DetectorType = Field(description="Detector classification (heuristic baseline, trained model, etc.)")

    synthetic_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Estimated probability score (0.0 to 1.0) indicating likelihood of synthetic generation"
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence score (0.0 to 1.0) in the assessment based on image features and detector capabilities"
    )
    assessment: str = Field(
        description="Neutral, probabilistic assessment summary regarding potential synthetic content"
    )
    indicators: List[str] = Field(
        default_factory=list,
        description="List of observed technical features or anomalies supporting the probabilistic assessment"
    )
    limitations: List[str] = Field(
        default_factory=list,
        description="Explicit forensic limitations, calibration constraints, and operational caveats"
    )
    features_used: List[str] = Field(
        default_factory=list,
        description="List of specific technical features evaluated during the analysis"
    )
    status: str = Field(default="COMPLETED", description="Status of the deepfake analysis run")

    def to_dict(self) -> dict:
        """Convert DeepfakeAnalysisResult to dictionary."""
        return self.model_dump()

    @classmethod
    def from_dict(cls, data: dict) -> "DeepfakeAnalysisResult":
        """Construct DeepfakeAnalysisResult from dictionary."""
        return cls(**data)

