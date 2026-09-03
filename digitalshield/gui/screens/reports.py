"""
Forensic Report Generation & Viewing Screen.
"""

import os
import queue
import subprocess
import webbrowser
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from digitalshield.gui.theme import Colors, Fonts
from digitalshield.gui.workers import ReportWorker


class ReportsScreen(ttk.Frame):
    """
    Generates PDF, HTML, and Markdown reports and allows one-click opening.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.msg_queue = queue.Queue()
        self.generated_files: dict = {}
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ttk.Frame(self, padding=(24, 16))
        header.pack(fill="x")

        back_btn = ttk.Button(
            header,
            text="← Back to Results",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("results"),
        )
        back_btn.pack(side="left")

        title = ttk.Label(header, text="Forensic Report Generation", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Content
        content = ttk.Frame(self, padding=24)
        content.pack(fill="both", expand=True)

        card = ttk.Frame(content, style="Card.TFrame", padding=24)
        card.pack(fill="x", pady=(0, 16))

        ttk.Label(card, text="Generate Forensic Report Packages", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 4))
        desc = (
            "Reports include comprehensive case parameters, evidence SHA-256 baselines, EXIF metadata, "
            "perceptual hashes, ELA findings, AI assessment caveats, timeline, and cryptographic audit logs."
        )
        ttk.Label(card, text=desc, style="CardMuted.TLabel", wraplength=720).pack(anchor="w", pady=(0, 20))

        # Generation Buttons
        btn_grid = ttk.Frame(card, style="Card.TFrame")
        btn_grid.pack(fill="x", pady=(0, 20))

        all_btn = ttk.Button(
            btn_grid,
            text="⭐ Generate All Formats (PDF, HTML, MD)",
            style="Primary.TButton",
            command=lambda: self._generate(["pdf", "html", "markdown"]),
        )
        all_btn.pack(side="left", padx=(0, 10))

        pdf_btn = ttk.Button(
            btn_grid,
            text="📄 Generate PDF",
            style="Secondary.TButton",
            command=lambda: self._generate(["pdf"]),
        )
        pdf_btn.pack(side="left", padx=(0, 10))

        html_btn = ttk.Button(
            btn_grid,
            text="🌐 Generate HTML",
            style="Secondary.TButton",
            command=lambda: self._generate(["html"]),
        )
        html_btn.pack(side="left", padx=(0, 10))

        # Status & Progress Area
        self.status_lbl = ttk.Label(card, text="Ready to generate reports.", style="CardMuted.TLabel", font=Fonts.SMALL)
        self.status_lbl.pack(anchor="w", pady=(0, 10))

        # File Access Card
        self.file_card = ttk.Frame(content, style="Card.TFrame", padding=20)
        self.file_card.pack(fill="x", pady=(0, 16))

        ttk.Label(self.file_card, text="Generated Report Files", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 8))

        self.file_status_lbl = ttk.Label(
            self.file_card,
            text="No reports generated in this session yet.",
            style="CardMuted.TLabel",
        )
        self.file_status_lbl.pack(anchor="w", pady=(0, 15))

        # Open actions
        self.action_frame = ttk.Frame(self.file_card, style="Card.TFrame")
        self.action_frame.pack(fill="x")

        self.open_pdf_btn = ttk.Button(
            self.action_frame,
            text="📂 Open PDF Document",
            style="Primary.TButton",
            command=self._open_pdf,
            state="disabled",
        )
        self.open_pdf_btn.pack(side="left", padx=(0, 10))

        self.open_html_btn = ttk.Button(
            self.action_frame,
            text="🌐 Open HTML in Browser",
            style="Secondary.TButton",
            command=self._open_html,
            state="disabled",
        )
        self.open_html_btn.pack(side="left", padx=(0, 10))

        self.open_folder_btn = ttk.Button(
            self.action_frame,
            text="📁 Open Report Folder",
            style="Outline.TButton",
            command=self._open_folder,
            state="disabled",
        )
        self.open_folder_btn.pack(side="left")

        # Bottom controls
        bottom_bar = ttk.Frame(content)
        bottom_bar.pack(fill="x", pady=(10, 0))

        new_inv_btn = ttk.Button(
            bottom_bar,
            text="📁 Start Another Investigation",
            style="Secondary.TButton",
            command=lambda: self.app.show_screen("new_case"),
        )
        new_inv_btn.pack(side="right")

    def _generate(self, formats: list):
        case = self.app.case_data.get("case")
        if not case:
            messagebox.showwarning("No Active Case", "No active case found to generate report for.")
            return

        self.status_lbl.config(text="Generating requested report formats in background...")
        worker = ReportWorker(
            case_id=case.case_id,
            formats=formats,
            msg_queue=self.msg_queue,
            base_dir=self.app.base_dir,
        )
        worker.start()
        self._check_queue()

    def _check_queue(self):
        try:
            while True:
                msg = self.msg_queue.get_nowait()
                m_type = msg.get("type")
                if m_type == "report_success":
                    record = msg.get("record")
                    file_map = msg.get("file_map", {})
                    self.generated_files.update(file_map)

                    self.status_lbl.config(text=f"✓ Report {record.report_id} generated successfully!")
                    
                    details_text = f"Report ID: {record.report_id}\n"
                    for fmt, path in self.generated_files.items():
                        details_text += f" • {fmt.upper()}: {path}\n"
                    self.file_status_lbl.config(text=details_text)

                    # Enable buttons
                    if "pdf" in self.generated_files:
                        self.open_pdf_btn.config(state="normal")
                    if "html" in self.generated_files:
                        self.open_html_btn.config(state="normal")
                    self.open_folder_btn.config(state="normal")

                    messagebox.showinfo(
                        "Report Generated",
                        f"Forensic report {record.report_id} generated successfully!",
                    )
                elif m_type == "report_error":
                    err = msg.get("error", "Unknown error")
                    self.status_lbl.config(text=f"Error generating report: {err}")
                    messagebox.showerror("Report Generation Error", f"Failed to generate report:\n{err}")

        except queue.Empty:
            self.after(100, self._check_queue)

    def _open_pdf(self):
        pdf_path = self.generated_files.get("pdf")
        if pdf_path and os.path.exists(pdf_path):
            os.startfile(pdf_path)
        else:
            messagebox.showwarning("File Missing", "PDF file not found on disk.")

    def _open_html(self):
        html_path = self.generated_files.get("html")
        if html_path and os.path.exists(html_path):
            webbrowser.open(Path(html_path).as_uri())
        else:
            messagebox.showwarning("File Missing", "HTML file not found on disk.")

    def _open_folder(self):
        first_file = next(iter(self.generated_files.values()), None)
        if first_file:
            folder = Path(first_file).parent
            if folder.exists():
                os.startfile(folder)
