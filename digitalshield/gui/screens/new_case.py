"""
New Case Investigation form with native Windows file picker.
"""

import os
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from digitalshield.evidence.manager import SUPPORTED_EXTENSIONS
from digitalshield.gui.theme import Colors, Fonts
from digitalshield.provenance.client import SafePublicClient


class NewCaseScreen(ttk.Frame):
    """
    Form to enter case parameters, select image evidence, and optionally record public source URL.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.selected_path: str = ""
        self._build_ui()

    def _build_ui(self):
        # Header Bar
        header = ttk.Frame(self, padding=(24, 12))
        header.pack(fill="x")

        back_btn = ttk.Button(
            header,
            text="← Back",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("home"),
        )
        back_btn.pack(side="left")

        title = ttk.Label(header, text="Start New Investigation", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Content area
        content = ttk.Frame(self, padding=(24, 10))
        content.pack(fill="both", expand=True)

        card = ttk.Frame(content, style="Card.TFrame", padding=(24, 16))
        card.pack(fill="x", pady=2)

        # 1. Investigator Name
        ttk.Label(card, text="Investigator / Analyst Name", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        self.investigator_var = tk.StringVar(value="Forensic Investigator")
        inv_entry = ttk.Entry(card, textvariable=self.investigator_var, font=Fonts.BODY)
        inv_entry.pack(fill="x", pady=(0, 10))

        # 2. Case Name
        ttk.Label(card, text="Case Name / Subject", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        self.case_name_var = tk.StringVar(value="Digital Evidence Investigation")
        case_entry = ttk.Entry(card, textvariable=self.case_name_var, font=Fonts.BODY)
        case_entry.pack(fill="x", pady=(0, 10))

        # 3. Description
        ttk.Label(card, text="Case Description (Optional)", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        self.desc_var = tk.StringVar(value="Image evidence imported for forensic integrity analysis.")
        desc_entry = ttk.Entry(card, textvariable=self.desc_var, font=Fonts.BODY)
        desc_entry.pack(fill="x", pady=(0, 10))

        # 4. Evidence File Picker
        ttk.Label(card, text="Evidence Image File", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        
        picker_frame = ttk.Frame(card, style="Card.TFrame")
        picker_frame.pack(fill="x", pady=(0, 4))

        choose_btn = ttk.Button(
            picker_frame,
            text="📁 Choose Image File...",
            style="Secondary.TButton",
            command=self._choose_file,
        )
        choose_btn.pack(side="left")

        self.file_lbl = ttk.Label(
            picker_frame,
            text="No file selected",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self.file_lbl.pack(side="left", padx=12)

        # Selected File Details preview
        self.details_lbl = ttk.Label(
            card,
            text="",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self.details_lbl.pack(anchor="w", pady=(0, 6))

        # 5. Public Source URL (Optional)
        ttk.Label(card, text="Public Source URL (Optional)", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        
        help_text = (
            "Enter public webpage URL where suspected media was observed (known observation source; not reverse-image search)."
        )
        ttk.Label(
            card,
            text=help_text,
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
            wraplength=760,
        ).pack(anchor="w", pady=(0, 2))

        self.source_url_var = tk.StringVar(value="")
        self.source_url_entry = ttk.Entry(card, textvariable=self.source_url_var, font=Fonts.BODY)
        self.source_url_entry.pack(fill="x", pady=(0, 2))

        example_hint = "Example: https://example.com/public-page-containing-the-image"
        ttk.Label(
            card,
            text=example_hint,
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        ).pack(anchor="w", pady=(0, 12))

        # Action Buttons
        btn_frame = ttk.Frame(card, style="Card.TFrame")
        btn_frame.pack(fill="x", pady=(4, 0))

        start_btn = ttk.Button(
            btn_frame,
            text="▶  Start Forensic Analysis",
            style="Primary.TButton",
            command=self._start_analysis,
        )
        start_btn.pack(side="right")

    def _choose_file(self):
        """Open native Windows file dialog filtered by supported image formats."""
        file_path = filedialog.askopenfilename(
            title="Select Evidence Image for Digital Forensics",
            filetypes=[
                ("Image Files", "*.jpg;*.jpeg;*.png;*.webp;*.gif;*.bmp;*.tiff"),
                ("All Supported Forensic Files", "*.jpg;*.jpeg;*.png;*.webp;*.gif;*.mp4;*.mov;*.avi;*.txt;*.pdf"),
                ("All Files", "*.*"),
            ],
        )
        if file_path:
            p = Path(file_path)
            # Validate format against backend supported extensions
            ext = p.suffix.lower()
            if ext not in SUPPORTED_EXTENSIONS:
                messagebox.showerror(
                    "Unsupported File Format",
                    f"Selected extension '{ext}' is not supported by EvidenceManager.\n"
                    f"Supported formats: {', '.join(sorted(SUPPORTED_EXTENSIONS.keys()))}",
                )
                return

            self.selected_path = file_path
            self.file_lbl.config(text=p.name, foreground=Colors.TEXT_MAIN, font=Fonts.BODY_BOLD)
            size_kb = p.stat().st_size / 1024
            self.details_lbl.config(
                text=f"Path: {file_path}\nSize: {size_kb:,.1f} KB  |  Format: {ext.upper()[1:]}"
            )

    def _start_analysis(self):
        """Validate inputs and transition to progress screen."""
        if not self.selected_path or not os.path.exists(self.selected_path):
            messagebox.showwarning("File Required", "Please choose a valid evidence image file first.")
            return

        case_name = self.case_name_var.get().strip() or "Untitled Case"
        investigator = self.investigator_var.get().strip() or "Unassigned"
        desc = self.desc_var.get().strip()

        # Validate Public Source URL if provided
        url_input = self.source_url_var.get().strip()
        validated_url = None
        if url_input:
            try:
                validated_url = SafePublicClient.validate_url(url_input)
            except ValueError as ve:
                messagebox.showerror(
                    "Invalid Public Source URL",
                    f"The provided Public Source URL is invalid or rejected by security policy:\n\n{ve}\n\n"
                    f"Please enter a valid public http:// or https:// URL, or leave the field blank."
                )
                return

        # Switch to Progress screen and start worker
        self.app.start_investigation(
            case_name=case_name,
            investigator=investigator,
            description=desc,
            image_path=self.selected_path,
            source_url=validated_url,
        )
