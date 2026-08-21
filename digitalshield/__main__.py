"""
Package entrypoint for running digitalshield as a module (`python -m digitalshield`).
"""

import sys
from digitalshield.cli.main import main

if __name__ == "__main__":
    sys.exit(main())
