"""
DigitalShield - Defensive Digital Forensics & Evidence Integrity Suite
"""

import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    # Load .env from project root if available
    _env_path = Path(__file__).resolve().parent.parent / ".env"
    if _env_path.exists():
        load_dotenv(dotenv_path=_env_path)
    else:
        load_dotenv()
except ImportError:
    pass

__version__ = "0.1.0"
__author__ = "DigitalShield Project Contributors"
