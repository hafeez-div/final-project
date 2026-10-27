"""
Live Analysis Progress Screen with interactive status checklist.
"""

import tkinter as tk
from tkinter import ttk
from digitalshield.gui.theme import Colors, Fonts


class ProgressScreen(ttk.Frame):
    """
    Shows animated progress and checklist for each forensic pipeline stage.
    """

    STEPS = [
        "Case Initialization & Local Vault Setup",
        "Evidence Vault Ingestion & Cryptographic SHA-256 Baseline",
        "Technical & EXIF Metadata Extraction",
        "Perceptual Hashing (aHash, dHash, pHash)",
        "Error Level Analysis (ELA) Compression Variance",
        "AI-Assisted Deepfake & Synthetic Media Evaluation",
        "Automatic Reverse Image Search & Public Web Discovery",
    ]

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.step_labels = []
        self._build_ui()
        self.bind("<Destroy>", self._on_destroy)

    def _on_destroy(self, event=None):
        """Clean up background progressbar animation when destroyed."""
        self.stop()

    def stop(self):
        """Stop progress bar animation safely."""
        try:
            if hasattr(self, "prog_bar"):
                self.prog_bar.stop()
        except Exception:
            pass

    def _build_ui(self):
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.48, anchor="center")

        title = ttk.Label(container, text="Forensic Analysis in Progress", style="Title.TLabel")
        title.pack(pady=(0, 5))

        self.status_lbl = ttk.Label(
            container,
            text="Executing secure forensic inspection pipeline...",
            style="Subtitle.TLabel",
        )
        self.status_lbl.pack(pady=(0, 20))

        # Progress bar
        self.prog_bar = ttk.Progressbar(
            container,
            mode="indeterminate",
            style="Accent.Horizontal.TProgressbar",
            length=500,
        )
        self.prog_bar.pack(pady=(0, 25))
        self.prog_bar.start(15)

        # Card checklist
        card = ttk.Frame(container, style="Card.TFrame", padding=20)
        card.pack(fill="x", padx=10)

        for step_text in self.STEPS:
            row = ttk.Frame(card, style="Card.TFrame")
            row.pack(fill="x", pady=4)

            icon_lbl = tk.Label(
                row,
                text="○",
                font=(Fonts.FAMILY, 11),
                bg=Colors.CARD_BG,
                fg=Colors.TEXT_MUTED,
                width=3,
            )
            icon_lbl.pack(side="left")

            text_lbl = ttk.Label(row, text=step_text, style="Card.TLabel")
            text_lbl.pack(side="left", padx=5)

            self.step_labels.append((icon_lbl, text_lbl))

        # Safety disclaimer
        note = ttk.Label(
            container,
            text="Original evidence file is read in read-only mode and preserved immutably.",
            style="Muted.TLabel",
        )
        note.pack(pady=(20, 0))

    def reset(self):
        """Reset checklist for a new run."""
        for icon_lbl, text_lbl in self.step_labels:
            icon_lbl.config(text="○", fg=Colors.TEXT_MUTED)
            text_lbl.config(style="Card.TLabel")
        self.status_lbl.config(text="Executing secure forensic inspection pipeline...")
        self.prog_bar.start(15)

    def set_step_running(self, step_idx: int, msg: str):
        """Mark a step as currently running."""
        if 0 <= step_idx < len(self.step_labels):
            icon, text = self.step_labels[step_idx]
            icon.config(text="⟳", fg=Colors.ACCENT)
            text.config(font=Fonts.BODY_BOLD)
            self.status_lbl.config(text=msg)

    def set_step_completed(self, step_idx: int, msg: str):
        """Mark a step as completed."""
        if 0 <= step_idx < len(self.step_labels):
            icon, text = self.step_labels[step_idx]
            icon.config(text="✓", fg=Colors.SUCCESS)
            text.config(font=Fonts.BODY)
