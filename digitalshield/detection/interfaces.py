"""
Interfaces and abstract base classes for DigitalShield deepfake and synthetic media detectors.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any

from digitalshield.detection.models import DeepfakeAnalysisResult, DetectorType


class BaseDeepfakeDetector(ABC):
    """
    Abstract base class for deepfake and synthetic media analysis detectors.
    Enables future pluggability of trained CNNs, ViTs, or ensemble models without
    modifying evidence ingestion, storage, or CLI reporting pipelines.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Name or identifier of the detector model."""
        pass

    @property
    @abstractmethod
    def detector_type(self) -> DetectorType:
        """Type/classification of the detector (heuristic baseline, trained model, etc.)."""
        pass

    @abstractmethod
    def analyze(
        self,
        evidence_path: Path,
        evidence_metadata: Dict[str, Any],
        derived_features: Optional[Dict[str, Any]] = None
    ) -> DeepfakeAnalysisResult:
        """
        Execute deepfake / synthetic media assessment on a read-only evidence file.

        Args:
            evidence_path: Absolute Path to the read-only preserved evidence image in vault.
            evidence_metadata: Metadata dictionary containing evidence_id, case_id, etc.
            derived_features: Optional dictionary of pre-computed derived features (e.g. ELA, hashes).

        Returns:
            DeepfakeAnalysisResult containing probabilistic assessments, indicators, and limitations.
        """
        pass
