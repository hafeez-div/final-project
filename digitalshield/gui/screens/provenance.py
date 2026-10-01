"""
Public Source & Provenance Screen (Phase 7 integration for Phase 9 Desktop GUI).
Allows investigators to record and verify publicly accessible source URLs
without automated web crawling or unauthorized account access.
"""

import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from typing import Any, Optional

from digitalshield.gui.theme import Colors, Fonts
from digitalshield.provenance.service import ProvenanceService


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get a value from either a Pydantic model or a dictionary."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class ProvenanceScreen(ttk.Frame):
    """
    GUI screen for entering public URLs and inspecting recorded provenance observations.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ttk.Frame(self, padding=(24, 14))
        header.pack(fill="x")

        back_btn = ttk.Button(
            header,
            text="← Back to Summary",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("results"),
        )
        back_btn.pack(side="left")

        title = ttk.Label(header, text="Public Source & Media Provenance", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Scrollable content area
        content = ttk.Frame(self, padding=24)
        content.pack(fill="both", expand=True)

        # 1. Informational & Legal Scope Box
        info_card = ttk.Frame(content, style="Card.TFrame", padding=14)
        info_card.pack(fill="x", pady=(0, 12))

        ttk.Label(
            info_card,
            text="ℹ️  PUBLIC PROVENANCE OBSERVATION",
            font=Fonts.SMALL_BOLD,
            foreground=Colors.ACCENT,
        ).pack(anchor="w", pady=(0, 4))

        info_text = (
            "Enter a publicly accessible URL where this evidence was observed. "
            "DigitalShield performs safe, defensive HTTP/HTTPS requests with strict SSRF controls. "
            "It never accesses private accounts, bypasses authentication, or performs unauthorized network scanning."
        )
        ttk.Label(
            info_card,
            text=info_text,
            style="CardMuted.TLabel",
            wraplength=760,
        ).pack(anchor="w")

        # 2. Form Card
        form_card = ttk.Frame(content, style="Card.TFrame", padding=16)
        form_card.pack(fill="x", pady=(0, 12))

        # Evidence Target Label
        self.target_lbl = ttk.Label(
            form_card,
            text="Target Evidence: Not available",
            font=Fonts.BODY_BOLD,
            foreground=Colors.TEXT_MAIN,
        )
        self.target_lbl.pack(anchor="w", pady=(0, 10))

        # Row 1: Public URL (Required)
        ttk.Label(form_card, text="Public Source URL * (HTTP/HTTPS Required)", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 2))
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(form_card, textvariable=self.url_var, font=Fonts.BODY)
        self.url_entry.pack(fill="x", pady=(0, 10))

        # Row 2: Two Columns (Observed Account & Media URL)
        row2 = ttk.Frame(form_card, style="Card.TFrame")
        row2.pack(fill="x", pady=(0, 10))

        col_left = ttk.Frame(row2, style="Card.TFrame")
        col_left.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Label(col_left, text="Observed Account / Handle (Optional)", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 2))
        self.account_var = tk.StringVar()
        ttk.Entry(col_left, textvariable=self.account_var, font=Fonts.BODY).pack(fill="x")

        col_right = ttk.Frame(row2, style="Card.TFrame")
        col_right.pack(side="right", fill="x", expand=True, padx=(6, 0))
        ttk.Label(col_right, text="Direct Public Media URL (Optional)", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 2))
        self.media_var = tk.StringVar()
        ttk.Entry(col_right, textvariable=self.media_var, font=Fonts.BODY).pack(fill="x")

        # Row 3: Two Columns (Source Timestamp & Notes)
        row3 = ttk.Frame(form_card, style="Card.TFrame")
        row3.pack(fill="x", pady=(0, 12))

        col_ts = ttk.Frame(row3, style="Card.TFrame")
        col_ts.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Label(col_ts, text="Visible Source Timestamp (Optional)", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 2))
        self.ts_var = tk.StringVar()
        ttk.Entry(col_ts, textvariable=self.ts_var, font=Fonts.BODY).pack(fill="x")

        col_notes = ttk.Frame(row3, style="Card.TFrame")
        col_notes.pack(side="right", fill="x", expand=True, padx=(6, 0))
        ttk.Label(col_notes, text="Investigator Notes (Optional)", style="CardMuted.TLabel").pack(anchor="w", pady=(0, 2))
        self.notes_var = tk.StringVar()
        ttk.Entry(col_notes, textvariable=self.notes_var, font=Fonts.BODY).pack(fill="x")

        # Submit Button & Status
        btn_bar = ttk.Frame(form_card, style="Card.TFrame")
        btn_bar.pack(fill="x")

        self.record_btn = ttk.Button(
            btn_bar,
            text="➕ Record Provenance Observation",
            style="Primary.TButton",
            command=self._record_provenance,
        )
        self.record_btn.pack(side="left")

        self.status_lbl = ttk.Label(btn_bar, text="", font=Fonts.SMALL, style="CardMuted.TLabel")
        self.status_lbl.pack(side="left", padx=12)

        # 3. Recorded Observations Log
        obs_card = ttk.Frame(content, style="Card.TFrame", padding=14)
        obs_card.pack(fill="both", expand=True, pady=(0, 14))

        ttk.Label(obs_card, text="Recorded Provenance Observations for Active Case", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 6))

        self.records_text = tk.Text(
            obs_card,
            wrap="word",
            font=Fonts.MONO,
            bg=Colors.CARD_BG,
            fg=Colors.TEXT_MAIN,
            relief="solid",
            borderwidth=1,
            padx=10,
            pady=10,
            height=6,
        )
        scrollbar = ttk.Scrollbar(obs_card, orient="vertical", command=self.records_text.yview)
        self.records_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self.records_text.pack(side="left", fill="both", expand=True)

        # 4. Action Bar
        bottom_bar = ttk.Frame(content)
        bottom_bar.pack(fill="x")

        details_btn = ttk.Button(
            bottom_bar,
            text="🔍 View Detailed Inspection",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("details"),
        )
        details_btn.pack(side="left")

        report_btn = ttk.Button(
            bottom_bar,
            text="📄 Generate Forensic Report",
            style="Secondary.TButton",
            command=lambda: self.app.show_screen("reports"),
        )
        report_btn.pack(side="right")

    def load_data(self, data: dict):
        """Populate screen with current case/evidence info and recorded provenance."""
        if not data:
            data = {}

        ev = data.get("evidence")
        case = data.get("case")

        if ev:
            fname = _get_val(ev, "original_filename", "Unknown")
            eid = _get_val(ev, "evidence_id", "Unknown")
            self.target_lbl.config(text=f"Target Evidence: {fname} ({eid})")
        else:
            self.target_lbl.config(text="Target Evidence: No active evidence loaded")

        self._refresh_records()

    def _refresh_records(self):
        """Display all recorded provenance records for active case in text area."""
        case = self.app.case_data.get("case") if self.app.case_data else None
        cid = _get_val(case, "case_id") if case else None

        self.records_text.config(state="normal")
        self.records_text.delete("1.0", "end")

        raw_bdir = getattr(self.app, "base_dir", None)
        base_dir = Path(raw_bdir) if isinstance(raw_bdir, (str, Path)) else None

        if cid:
            try:
                service = ProvenanceService(base_dir=base_dir)
                records = service.list_provenance_by_case(cid)
            except Exception:
                records = []

            if records:
                self.records_text.insert("end", f"=== {len(records)} PROVENANCE RECORD(S) REGISTERED ===\n\n")
                for r in records:
                    pid = _get_val(r, "provenance_id", "N/A")
                    url = _get_val(r, "source_url", "N/A")
                    domain = _get_val(r, "source_domain", "N/A")
                    account = _get_val(r, "observed_account_name") or "Not recorded"
                    sim = _get_val(r, "similarity_score")
                    sim_str = f"{sim:.4f}" if sim is not None else "N/A (No media matching)"
                    status = _get_val(r, "source_status", "N/A")
                    ts = (_get_val(r, "discovery_timestamp") or "N/A")[:19].replace("T", " ")
                    assess = _get_val(r, "assessment", "")

                    self.records_text.insert("end", f"[{pid}] Domain: {domain} | Status: {status} | Obs Time: {ts}\n")
                    self.records_text.insert("end", f"  URL:             {url}\n")
                    self.records_text.insert("end", f"  Observed Account:{account}\n")
                    self.records_text.insert("end", f"  Similarity Score:{sim_str}\n")
                    self.records_text.insert("end", f"  Assessment:      {assess}\n\n")
            else:
                self.records_text.insert("end", "No public provenance records registered for this case.\n")
                self.records_text.insert("end", "Use the form above to record a public URL observation.\n")
        else:
            self.records_text.insert("end", "No active case selected.\n")

        self.records_text.config(state="disabled")

    def _record_provenance(self):
        """Call backend ProvenanceService to record public URL observation safely."""
        ev = self.app.case_data.get("evidence") if self.app.case_data else None
        if not ev:
            messagebox.showwarning("Evidence Required", "No active evidence selected to link provenance with.")
            return

        evidence_id = _get_val(ev, "evidence_id")
        source_url = self.url_var.get().strip()

        if not source_url:
            messagebox.showwarning("URL Required", "Please enter a valid public HTTP or HTTPS URL.")
            return

        observed_account = self.account_var.get().strip() or None
        media_url = self.media_var.get().strip() or None
        source_ts = self.ts_var.get().strip() or None
        notes = self.notes_var.get().strip() or None

        self.status_lbl.config(text="Validating and fetching public URL...", foreground=Colors.ACCENT)

        try:
            raw_bdir = getattr(self.app, "base_dir", None)
            base_dir = Path(raw_bdir) if isinstance(raw_bdir, (str, Path)) else None
            service = ProvenanceService(base_dir=base_dir)
            record = service.record_provenance(
                evidence_id=evidence_id,
                source_url=source_url,
                observed_account_name=observed_account,
                media_url=media_url,
                source_timestamp=source_ts,
                notes=notes,
            )

            self.status_lbl.config(
                text=f"✓ Recorded: {record.provenance_id} ({record.source_status})",
                foreground=Colors.SUCCESS,
            )

            # Clear inputs
            self.url_var.set("")
            self.account_var.set("")
            self.media_var.set("")
            self.ts_var.set("")
            self.notes_var.set("")

            # Refresh display
            self._refresh_records()

            messagebox.showinfo(
                "Provenance Recorded",
                f"Provenance observation successfully recorded as {record.provenance_id}.\n"
                f"Source Domain: {record.source_domain}\n"
                f"Status: {record.source_status}",
            )

        except ValueError as ve:
            self.status_lbl.config(text="Safety/Validation error.", foreground=Colors.DANGER)
            messagebox.showerror(
                "URL Safety Rejection",
                f"This URL cannot be accessed because it does not meet DigitalShield's public-source safety requirements:\n\n{ve}",
            )
        except Exception as e:
            self.status_lbl.config(text="Error recording provenance.", foreground=Colors.DANGER)
            messagebox.showerror("Error", f"Failed to record provenance observation: {e}")
