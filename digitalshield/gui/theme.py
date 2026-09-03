"""
GUI Theme and styling definitions for DigitalShield.
Professional forensic theme with clean typography, contrast, and modern ttk styles.
"""

import tkinter as tk
from tkinter import ttk


class Colors:
    # Palette
    PRIMARY = "#0f172a"        # Deep slate navy
    PRIMARY_LIGHT = "#1e293b"  # Lighter slate
    SECONDARY = "#334155"      # Border/muted slate
    ACCENT = "#0284c7"         # Professional cyan/blue
    ACCENT_HOVER = "#0369a1"   # Darker accent
    SUCCESS = "#16a34a"        # Forest green
    SUCCESS_LIGHT = "#dcfce7"  # Light green background
    WARNING = "#d97706"        # Amber/orange
    WARNING_LIGHT = "#fef3c7"  # Light amber background
    DANGER = "#dc2626"         # Red
    DANGER_LIGHT = "#fee2e2"   # Light red background
    
    BG = "#f8fafc"             # Window background (light gray/blue)
    CARD_BG = "#ffffff"        # White card backgrounds
    CARD_BORDER = "#e2e8f0"    # Light border
    
    TEXT_MAIN = "#0f172a"      # Dark text
    TEXT_MUTED = "#64748b"     # Secondary text
    TEXT_LIGHT = "#94a3b8"     # Placeholder text
    TEXT_WHITE = "#ffffff"     # Pure white text


class Fonts:
    FAMILY = "Segoe UI"
    
    TITLE = (FAMILY, 18, "bold")
    SUBTITLE = (FAMILY, 12, "bold")
    HEADING = (FAMILY, 11, "bold")
    BODY = (FAMILY, 10, "normal")
    BODY_BOLD = (FAMILY, 10, "bold")
    SMALL = (FAMILY, 9, "normal")
    SMALL_BOLD = (FAMILY, 9, "bold")
    MONO = ("Consolas", 9, "normal")
    MONO_BOLD = ("Consolas", 9, "bold")


def apply_theme(root: tk.Tk):
    """Apply global ttk styles to root window."""
    style = ttk.Style(root)
    
    available = style.theme_names()
    if "clam" in available:
        style.theme_use("clam")
    elif "vista" in available:
        style.theme_use("vista")
        
    root.configure(bg=Colors.BG)
    
    style.configure("TFrame", background=Colors.BG)
    style.configure("Card.TFrame", background=Colors.CARD_BG, relief="solid", borderwidth=1)
    style.configure("DarkCard.TFrame", background=Colors.PRIMARY_LIGHT, relief="solid", borderwidth=1)
    
    style.configure("TLabel", background=Colors.BG, foreground=Colors.TEXT_MAIN, font=Fonts.BODY)
    style.configure("Card.TLabel", background=Colors.CARD_BG, foreground=Colors.TEXT_MAIN, font=Fonts.BODY)
    style.configure("Title.TLabel", background=Colors.BG, foreground=Colors.PRIMARY, font=Fonts.TITLE)
    style.configure("Subtitle.TLabel", background=Colors.BG, foreground=Colors.TEXT_MUTED, font=Fonts.SUBTITLE)
    style.configure("Heading.TLabel", background=Colors.BG, foreground=Colors.PRIMARY, font=Fonts.HEADING)
    style.configure("CardHeading.TLabel", background=Colors.CARD_BG, foreground=Colors.PRIMARY, font=Fonts.HEADING)
    style.configure("Muted.TLabel", background=Colors.BG, foreground=Colors.TEXT_MUTED, font=Fonts.SMALL)
    style.configure("CardMuted.TLabel", background=Colors.CARD_BG, foreground=Colors.TEXT_MUTED, font=Fonts.SMALL)
    
    style.configure(
        "Primary.TButton",
        font=Fonts.BODY_BOLD,
        background=Colors.ACCENT,
        foreground=Colors.TEXT_WHITE,
        borderwidth=0,
        padding=(14, 7),
    )
    style.map(
        "Primary.TButton",
        background=[("active", Colors.ACCENT_HOVER), ("disabled", Colors.SECONDARY)],
        foreground=[("active", Colors.TEXT_WHITE), ("disabled", Colors.TEXT_LIGHT)],
    )
    
    style.configure(
        "Secondary.TButton",
        font=Fonts.BODY,
        background=Colors.PRIMARY_LIGHT,
        foreground=Colors.TEXT_WHITE,
        borderwidth=0,
        padding=(12, 6),
    )
    style.map(
        "Secondary.TButton",
        background=[("active", Colors.PRIMARY)],
    )

    style.configure(
        "Outline.TButton",
        font=Fonts.BODY,
        background=Colors.CARD_BG,
        foreground=Colors.PRIMARY,
        relief="solid",
        borderwidth=1,
        padding=(12, 6),
    )
    style.map(
        "Outline.TButton",
        background=[("active", Colors.BG)],
    )
    
    style.configure(
        "TEntry",
        padding=6,
        fieldbackground=Colors.CARD_BG,
        foreground=Colors.TEXT_MAIN,
        font=Fonts.BODY,
    )
    
    style.configure(
        "Accent.Horizontal.TProgressbar",
        troughcolor=Colors.BG,
        background=Colors.ACCENT,
        bordercolor=Colors.CARD_BORDER,
        lightcolor=Colors.ACCENT,
        darkcolor=Colors.ACCENT,
    )
    
    style.configure("TNotebook", background=Colors.BG, borderwidth=0)
    style.configure("TNotebook.Tab", padding=(12, 5), font=Fonts.BODY_BOLD)
    style.map(
        "TNotebook.Tab",
        background=[("selected", Colors.CARD_BG), ("!selected", Colors.BG)],
        foreground=[("selected", Colors.ACCENT), ("!selected", Colors.TEXT_MUTED)],
    )
