"""
Main Tkinter Application Coordinator for DigitalShield.
"""

import queue
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk
from typing import Optional

from digitalshield.gui.theme import Colors, apply_theme
from digitalshield.gui.workers import AnalysisWorker
from digitalshield.gui.screens.home import HomeScreen
from digitalshield.gui.screens.new_case import NewCaseScreen
from digitalshield.gui.screens.progress import ProgressScreen
from digitalshield.gui.screens.results import ResultsScreen
from digitalshield.gui.screens.details import DetailsScreen
from digitalshield.gui.screens.provenance import ProvenanceScreen
from digitalshield.gui.screens.reports import ReportsScreen
from digitalshield.gui.screens.open_case import OpenCaseScreen


class DigitalShieldApp(tk.Tk):
    """
    Main application window managing navigation and shared state.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        super().__init__()
        self.base_dir = base_dir
        self.case_data: dict = {}
        self.msg_queue = queue.Queue()

        # Window configuration
        self.title("DigitalShield — Digital Forensic Assistant")
        self.geometry("880x720")
        self.minsize(800, 620)

        # Center on screen
        self._center_window(880, 720)

        # Apply custom theme
        apply_theme(self)

        # Root container for screens
        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Register screens
        self.screens = {}
        for ScreenClass, name in [
            (HomeScreen, "home"),
            (NewCaseScreen, "new_case"),
            (ProgressScreen, "progress"),
            (ResultsScreen, "results"),
            (DetailsScreen, "details"),
            (ProvenanceScreen, "provenance"),
            (ReportsScreen, "reports"),
            (OpenCaseScreen, "open_case"),
        ]:
            screen = ScreenClass(self.container, self)
            self.screens[name] = screen
            screen.grid(row=0, column=0, sticky="nsew")

        # Show Home Screen
        self.show_screen("home")

    def _center_window(self, width: int, height: int):
        try:
            self.update_idletasks()
            sw = self.winfo_screenwidth()
            sh = self.winfo_screenheight()
            x = max(0, (sw - width) // 2)
            y = max(0, (sh - height) // 2)
            self.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            pass

    def show_screen(self, name: str):
        """Switch active screen."""
        screen = self.screens.get(name)
        if screen:
            if name == "open_case" and hasattr(screen, "refresh_cases"):
                screen.refresh_cases()
            elif name in ("results", "details", "provenance") and hasattr(screen, "load_data") and self.case_data:
                screen.load_data(self.case_data)

            screen.tkraise()

    def start_investigation(
        self,
        case_name: str,
        investigator: str,
        description: str,
        image_path: str,
        source_url: Optional[str] = None,
    ):
        """Initiate background forensic analysis pipeline."""
        progress_screen = self.screens.get("progress")
        if progress_screen:
            progress_screen.reset()

        self.show_screen("progress")

        worker = AnalysisWorker(
            case_name=case_name,
            investigator=investigator,
            description=description,
            image_path=Path(image_path),
            msg_queue=self.msg_queue,
            base_dir=self.base_dir,
            source_url=source_url,
        )
        worker.start()
        self._poll_analysis_queue()

    def _poll_analysis_queue(self):
        """Check worker messages safely from main Tkinter thread."""
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                m_type = msg.get("type")

                progress_screen = self.screens.get("progress")
                if m_type == "step_start":
                    if progress_screen:
                        progress_screen.set_step_running(msg.get("step", 0), msg.get("msg", ""))
                elif m_type == "step_done":
                    if progress_screen:
                        progress_screen.set_step_completed(msg.get("step", 0), msg.get("msg", ""))
                elif m_type == "complete":
                    if progress_screen:
                        progress_screen.stop()
                    self.case_data = msg.get("data", {})
                    self.show_screen("results")
                    return
                elif m_type == "error":
                    if progress_screen:
                        progress_screen.stop()
                    err = msg.get("error", "Unknown error")
                    messagebox.showerror("Analysis Error", f"Forensic analysis failed:\n{err}")
                    self.show_screen("new_case")
                    return

        except queue.Empty:
            self.after(100, self._poll_analysis_queue)


def launch_gui(base_dir: Optional[Path] = None):
    """Launch DigitalShield Desktop GUI."""
    app = DigitalShieldApp(base_dir=base_dir)
    app.mainloop()


def main():
    launch_gui()


if __name__ == "__main__":
    main()
