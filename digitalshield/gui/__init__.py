"""
DigitalShield Desktop GUI package.
"""

import os
import sys
from pathlib import Path

# Ensure Tcl/Tk libraries can be located on Windows Python installs if not already in env
if sys.platform == "win32":
    tcl_dir = Path(sys.prefix) / "tcl"
    tcl_lib = tcl_dir / "tcl8.6"
    tk_lib = tcl_dir / "tk8.6"
    if tcl_lib.exists() and "TCL_LIBRARY" not in os.environ:
        os.environ["TCL_LIBRARY"] = tcl_lib.as_posix()
    if tk_lib.exists() and "TK_LIBRARY" not in os.environ:
        os.environ["TK_LIBRARY"] = tk_lib.as_posix()

from digitalshield.gui.app import DigitalShieldApp, launch_gui, main

__all__ = ["DigitalShieldApp", "launch_gui", "main"]

