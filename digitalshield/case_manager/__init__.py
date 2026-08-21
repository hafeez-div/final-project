"""
Case Manager package responsible for case creation, metadata tracking, and lifecycle administration.
"""

from digitalshield.case_manager.models import Case
from digitalshield.case_manager.manager import CaseManager

__all__ = ["Case", "CaseManager"]
