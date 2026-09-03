"""
Results Summary Screen presenting high-level forensic findings.
"""

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional
from digitalshield.gui.theme import Colors, Fonts


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get a value from either a Pydantic model or a dictionary."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class ResultsScreen(ttk.Frame):
    """
    Displays summary findings, indicator scores, and report generation triggers.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ttk.Frame(self, padding=(24, 16))
        header.pack(fill="x")

        home_btn = ttk.Button(
            header,
            text="⌂ Home",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("home"),
        )
        home_btn.pack(side="left")

        title = ttk.Label(header, text="Forensic Analysis Findings", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Scrollable content
        content = ttk.Frame(self, padding=24)
        content.pack(fill="both", expand=True)

        # 1. Evidence Card
        ev_card = ttk.Frame(content, style="Card.TFrame", padding=16)
        ev_card.pack(fill="x", pady=(0, 14))

        self.ev_title_lbl = ttk.Label(ev_card, text="Evidence Item: Not available", style="CardHeading.TLabel")
        self.ev_title_lbl.pack(anchor="w", pady=(0, 4))

        self.ev_hash_lbl = ttk.Label(
            ev_card,
            text="SHA-256 Digest: Not available",
            style="Card.TLabel",
            font=Fonts.MONO,
        )
        self.ev_hash_lbl.pack(anchor="w", pady=(0, 2))

        self.ev_meta_lbl = ttk.Label(ev_card, text="Status: No evidence loaded", style="CardMuted.TLabel")
        self.ev_meta_lbl.pack(anchor="w")

        # 2. Findings Grid (2 Columns)
        grid_frame = ttk.Frame(content)
        grid_frame.pack(fill="x", pady=(0, 14))

        # ELA Card (Left)
        ela_card = ttk.Frame(grid_frame, style="Card.TFrame", padding=16)
        ela_card.pack(side="left", fill="both", expand=True, padx=(0, 7))

        ttk.Label(ela_card, text="Error Level Analysis (ELA)", style="CardHeading.TLabel").pack(anchor="w")
        self.ela_score_lbl = ttk.Label(
            ela_card,
            text="Anomaly Score: Not available",
            font=Fonts.SUBTITLE,
            foreground=Colors.ACCENT,
        )
        self.ela_score_lbl.pack(anchor="w", pady=(6, 4))

        self.ela_desc_lbl = ttk.Label(
            ela_card,
            text="No Error Level Analysis (ELA) performed on this evidence.",
            style="CardMuted.TLabel",
            wraplength=350,
        )
        self.ela_desc_lbl.pack(anchor="w")

        # Deepfake Card (Right)
        df_card = ttk.Frame(grid_frame, style="Card.TFrame", padding=16)
        df_card.pack(side="right", fill="both", expand=True, padx=(7, 0))

        ttk.Label(df_card, text="AI Deepfake / Synthetic Media", style="CardHeading.TLabel").pack(anchor="w")
        self.df_score_lbl = ttk.Label(
            df_card,
            text="Synthetic Probability: Not available",
            font=Fonts.SUBTITLE,
            foreground=Colors.ACCENT,
        )
        self.df_score_lbl.pack(anchor="w", pady=(6, 4))

        self.df_desc_lbl = ttk.Label(
            df_card,
            text="No synthetic media assessment performed on this evidence.",
            style="CardMuted.TLabel",
            wraplength=350,
        )
        self.df_desc_lbl.pack(anchor="w")

        # 3. Forensic Caution Notice Box
        caution_box = ttk.Frame(content, style="Card.TFrame", padding=14)
        caution_box.pack(fill="x", pady=(0, 20))

        caution_lbl = ttk.Label(
            caution_box,
            text="⚠️  FORENSIC NOTICE & LEGAL LIMITATIONS",
            font=Fonts.SMALL_BOLD,
            foreground=Colors.WARNING,
        )
        caution_lbl.pack(anchor="w", pady=(0, 4))

        disclaimer_text = (
            "All analysis results are probabilistic derived forensic indicators and must be evaluated alongside "
            "independent corroborating evidence. DigitalShield does not determine legal guilt, civil liability, "
            "authorship, or criminal responsibility."
        )
        disclaimer_lbl = ttk.Label(
            caution_box,
            text=disclaimer_text,
            style="CardMuted.TLabel",
            wraplength=760,
        )
        disclaimer_lbl.pack(anchor="w")

        # 4. Action Buttons
        btn_bar = ttk.Frame(content)
        btn_bar.pack(fill="x")

        details_btn = ttk.Button(
            btn_bar,
            text="🔍  View Detailed Results",
            style="Secondary.TButton",
            command=lambda: self.app.show_screen("details"),
        )
        details_btn.pack(side="left")

        report_btn = ttk.Button(
            btn_bar,
            text="📄  Generate Forensic Report",
            style="Primary.TButton",
            command=lambda: self.app.show_screen("reports"),
        )
        report_btn.pack(side="right")

    def load_data(self, data: dict):
        """Populate results from active case data."""
        if not data:
            data = {}

        ev = data.get("evidence")
        ela = data.get("ela")
        df = data.get("deepfake")

        if ev:
            fname = _get_val(ev, "original_filename", "Unknown")
            eid = _get_val(ev, "evidence_id", "Unknown")
            sha = _get_val(ev, "sha256", "Not available")
            fsize = _get_val(ev, "file_size", 0)
            mime = _get_val(ev, "mime_type", "Unknown")
            size_kb = fsize / 1024 if fsize else 0.0

            self.ev_title_lbl.config(text=f"Evidence Item: {fname} ({eid})")
            self.ev_hash_lbl.config(text=f"SHA-256: {sha}")
            self.ev_meta_lbl.config(text=f"Size: {size_kb:,.1f} KB  |  MIME: {mime}  |  Preserved in Vault")
        else:
            self.ev_title_lbl.config(text="Evidence Item: Not available")
            self.ev_hash_lbl.config(text="SHA-256: Not available")
            self.ev_meta_lbl.config(text="Status: No evidence loaded")

        if ela:
            score = _get_val(ela, "anomaly_score")
            conf = _get_val(ela, "confidence")
            assess = _get_val(ela, "assessment", "Error Level Analysis complete.")

            if score is not None and conf is not None:
                self.ela_score_lbl.config(text=f"Anomaly Score: {score:.4f}  (Conf: {conf*100:.0f}%)")
            elif score is not None:
                self.ela_score_lbl.config(text=f"Anomaly Score: {score:.4f}")
            else:
                self.ela_score_lbl.config(text="Anomaly Score: Not available")
            self.ela_desc_lbl.config(text=assess)
        else:
            self.ela_score_lbl.config(text="Anomaly Score: Not available")
            self.ela_desc_lbl.config(text="No Error Level Analysis (ELA) performed on this evidence.")

        if df:
            prob = _get_val(df, "synthetic_probability")
            conf = _get_val(df, "confidence")
            assess = _get_val(df, "assessment", "Synthetic media evaluation complete.")

            if prob is not None and conf is not None:
                self.df_score_lbl.config(text=f"Synthetic Prob: {prob*100:.1f}%  (Conf: {conf*100:.0f}%)")
            elif prob is not None:
                self.df_score_lbl.config(text=f"Synthetic Prob: {prob*100:.1f}%")
            else:
                self.df_score_lbl.config(text="Synthetic Prob: Not available")
            self.df_desc_lbl.config(text=assess)
        else:
            self.df_score_lbl.config(text="Synthetic Prob: Not available")
            self.df_desc_lbl.config(text="No synthetic media assessment performed on this evidence.")
