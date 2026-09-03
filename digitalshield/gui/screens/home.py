"""
Home Screen for DigitalShield Desktop GUI.
"""

import tkinter as tk
from tkinter import ttk
from digitalshield.gui.theme import Colors, Fonts


class HomeScreen(ttk.Frame):
    """
    Home landing screen presenting primary actions to the user.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Center container
        container = ttk.Frame(self)
        container.place(relx=0.5, rely=0.48, anchor="center")

        # Shield Icon & Branding
        icon_lbl = tk.Label(
            container,
            text="🛡️",
            font=(Fonts.FAMILY, 44),
            bg=Colors.BG,
            fg=Colors.ACCENT,
        )
        icon_lbl.pack(pady=(0, 5))

        title_lbl = ttk.Label(
            container,
            text="DIGITALSHIELD",
            style="Title.TLabel",
        )
        title_lbl.pack(pady=(0, 2))

        sub_lbl = ttk.Label(
            container,
            text="Defensive Digital Forensics & Evidence Verification Suite",
            style="Subtitle.TLabel",
        )
        sub_lbl.pack(pady=(0, 10))

        tagline = ttk.Label(
            container,
            text="Protect  •  Preserve  •  Analyze  •  Report",
            style="Muted.TLabel",
            font=Fonts.SMALL_BOLD,
        )
        tagline.pack(pady=(0, 30))

        # Card with buttons
        card = ttk.Frame(container, style="Card.TFrame", padding=25)
        card.pack(fill="x", padx=10)

        new_btn = ttk.Button(
            card,
            text="📁  Start New Investigation",
            style="Primary.TButton",
            command=lambda: self.app.show_screen("new_case"),
        )
        new_btn.pack(fill="x", pady=6, ipady=4)

        open_btn = ttk.Button(
            card,
            text="📂  Open Existing Case",
            style="Secondary.TButton",
            command=lambda: self.app.show_screen("open_case"),
        )
        open_btn.pack(fill="x", pady=6, ipady=4)

        exit_btn = ttk.Button(
            card,
            text="✕  Exit",
            style="Outline.TButton",
            command=self.app.destroy,
        )
        exit_btn.pack(fill="x", pady=(6, 0), ipady=3)

        # Footer
        footer = ttk.Label(
            self,
            text="Academic Forensic Project • 100% Local & Offline • Evidence-Preserving",
            style="Muted.TLabel",
        )
        footer.pack(side="bottom", pady=15)
