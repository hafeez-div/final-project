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
        # 1. Header (fixed at top)
        header = ttk.Frame(self, padding=(24, 14))
        header.pack(side="top", fill="x")

        back_btn = ttk.Button(
            header,
            text="← Back to Summary",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("results"),
        )
        back_btn.pack(side="left")

        title = ttk.Label(header, text="Public Source & Media Provenance", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # 2. Fixed bottom footer (packed at side="bottom" first so it stays persistently visible)
        footer = ttk.Frame(self, padding=(24, 12))
        footer.pack(side="bottom", fill="x")

        details_btn = ttk.Button(
            footer,
            text="🔍 View Detailed Inspection",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("details"),
        )
        details_btn.pack(side="left")

        report_btn = ttk.Button(
            footer,
            text="📄 Generate Forensic Report",
            style="Secondary.TButton",
            command=lambda: self.app.show_screen("reports"),
        )
        report_btn.pack(side="right")

        # 3. Middle scrollable area (canvas + scrollbar)
        middle = ttk.Frame(self)
        middle.pack(side="top", fill="both", expand=True)

        canvas = tk.Canvas(middle, bg=Colors.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(middle, orient="vertical", command=canvas.yview)
        scroll_content = ttk.Frame(canvas, padding=(24, 8))

        scroll_content.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas_window = canvas.create_window((0, 0), window=scroll_content, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def _on_canvas_resize(event):
            canvas.itemconfig(canvas_window, width=event.width)

        canvas.bind("<Configure>", _on_canvas_resize)

        def _on_mousewheel(event):
            if self.winfo_ismapped():
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        # 1. Informational & Legal Scope Box
        info_card = ttk.Frame(scroll_content, style="Card.TFrame", padding=14)
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

        # 2. Form Card with 2-Column Grid Alignment
        form_card = ttk.Frame(scroll_content, style="Card.TFrame", padding=16)
        form_card.pack(fill="x", pady=(0, 12))

        form_card.columnconfigure(0, weight=1, uniform="prov_col")
        form_card.columnconfigure(1, weight=1, uniform="prov_col")

        # Evidence Target Label (Spans 2 columns)
        self.target_lbl = ttk.Label(
            form_card,
            text="Target Evidence: Not available",
            font=Fonts.BODY_BOLD,
            foreground=Colors.TEXT_MAIN,
        )
        self.target_lbl.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # Row 1: Public Source URL Label (Spans 2 columns)
        ttk.Label(form_card, text="Public Source URL * (HTTP/HTTPS Required)", style="CardHeading.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(0, 2)
        )

        # Row 2: Public Source URL Entry (Spans 2 columns)
        self.url_var = tk.StringVar()
        self.url_entry = ttk.Entry(form_card, textvariable=self.url_var, font=Fonts.BODY)
        self.url_entry.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        # Row 3: Two Column Labels (Observed Account & Direct Media URL)
        ttk.Label(form_card, text="Observed Account / Handle (Optional)", style="CardMuted.TLabel").grid(
            row=3, column=0, sticky="w", padx=(0, 8), pady=(0, 2)
        )
        ttk.Label(form_card, text="Direct Public Media URL (Optional)", style="CardMuted.TLabel").grid(
            row=3, column=1, sticky="w", padx=(8, 0), pady=(0, 2)
        )

        # Row 4: Two Column Entries
        self.account_var = tk.StringVar()
        self.account_entry = ttk.Entry(form_card, textvariable=self.account_var, font=Fonts.BODY)
        self.account_entry.grid(row=4, column=0, sticky="ew", padx=(0, 8), pady=(0, 10))

        self.media_var = tk.StringVar()
        self.media_entry = ttk.Entry(form_card, textvariable=self.media_var, font=Fonts.BODY)
        self.media_entry.grid(row=4, column=1, sticky="ew", padx=(8, 0), pady=(0, 10))

        # Row 5: Two Column Labels (Source Timestamp & Notes)
        ttk.Label(form_card, text="Visible Source Timestamp (Optional)", style="CardMuted.TLabel").grid(
            row=5, column=0, sticky="w", padx=(0, 8), pady=(0, 2)
        )
        ttk.Label(form_card, text="Investigator Notes (Optional)", style="CardMuted.TLabel").grid(
            row=5, column=1, sticky="w", padx=(8, 0), pady=(0, 2)
        )

        # Row 6: Two Column Entries
        self.ts_var = tk.StringVar()
        self.ts_entry = ttk.Entry(form_card, textvariable=self.ts_var, font=Fonts.BODY)
        self.ts_entry.grid(row=6, column=0, sticky="ew", padx=(0, 8), pady=(0, 12))

        self.notes_var = tk.StringVar()
        self.notes_entry = ttk.Entry(form_card, textvariable=self.notes_var, font=Fonts.BODY)
        self.notes_entry.grid(row=6, column=1, sticky="ew", padx=(8, 0), pady=(0, 12))

        # Row 7: Submit Button & Status
        btn_bar = ttk.Frame(form_card, style="Card.TFrame")
        btn_bar.grid(row=7, column=0, columnspan=2, sticky="ew", pady=(2, 0))

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
        obs_card = ttk.Frame(scroll_content, style="Card.TFrame", padding=14)
        obs_card.pack(fill="both", expand=True, pady=(0, 8))

        ttk.Label(obs_card, text="Recorded Provenance Observations for Active Case", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 6))

        text_frame = ttk.Frame(obs_card)
        text_frame.pack(fill="both", expand=True)

        self.records_text = tk.Text(
            text_frame,
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
        scrollbar_records = ttk.Scrollbar(text_frame, orient="vertical", command=self.records_text.yview)
        self.records_text.configure(yscrollcommand=scrollbar_records.set)
        scrollbar_records.pack(side="right", fill="y")
        self.records_text.pack(side="left", fill="both", expand=True)

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
