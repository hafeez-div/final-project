"""
Detection package providing interfaces for image manipulation heuristics, Error Level Analysis (ELA), and deepfake probabilistic assessments.
"""

from digitalshield.detection.models import ELAResult, ELAStatistics, DeepfakeAnalysisResult, DetectorType
from digitalshield.detection.ela import ELADetector
from digitalshield.detection.interfaces import BaseDeepfakeDetector
from digitalshield.detection.deepfake import BaselineDeepfakeDetector, DeepfakeAssessmentService

__all__ = [
    "ELAResult",
    "ELAStatistics",
    "ELADetector",
    "BaseDeepfakeDetector",
    "BaselineDeepfakeDetector",
    "DeepfakeAssessmentService",
    "DeepfakeAnalysisResult",
    "DetectorType",
]

