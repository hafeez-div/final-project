"""
Results Summary Screen presenting high-level forensic findings.

Includes the full-width Automatic Reverse Image Search section displaying
the search provider, status, timestamps, candidate counts, verified matches,
and a structured results table with clickable source links.
"""

import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk
from typing import Any, List, Optional

from digitalshield.gui.theme import Colors, Fonts
from digitalshield.web_discovery.service import WebDiscoveryService


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
    Includes the Automatic Reverse Image Search & Public Web Discovery findings table.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._evidence_id: Optional[str] = None
        self._wd_service: Optional[WebDiscoveryService] = None
        self._build_ui()

    @property
    def wd_service(self) -> WebDiscoveryService:
        if self._wd_service is None:
            base_dir = getattr(self.app, "base_dir", None)
            self._wd_service = WebDiscoveryService(base_dir=base_dir)
        return self._wd_service

    # ------------------------------------------------------------------ UI --

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

        # Scrollable outer frame
        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True)

        canvas = tk.Canvas(outer, bg=Colors.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        self._scroll_frame = ttk.Frame(canvas)

        self._scroll_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_window = canvas.create_window((0, 0), window=self._scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        def _on_canvas_resize(event):
            canvas.itemconfig(canvas_window, width=event.width)
        canvas.bind("<Configure>", _on_canvas_resize)

        scrollbar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        pad = {"padx": 24}

        # --- Section 1: Evidence Item Details ---
        ev_card = ttk.Frame(self._scroll_frame, style="Card.TFrame", padding=16)
        ev_card.pack(fill="x", pady=(14, 8), **pad)

        ttk.Label(ev_card, text="Preserved Digital Evidence", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 6))
        self.ev_title_lbl = ttk.Label(ev_card, text="Evidence Item: Not loaded", style="CardHeading.TLabel", font=Fonts.BODY_BOLD)
        self.ev_title_lbl.pack(anchor="w", pady=(0, 4))

        self.ev_hash_lbl = ttk.Label(ev_card, text="SHA-256: Not available", style="CardMuted.TLabel", font=Fonts.MONO)
        self.ev_hash_lbl.pack(anchor="w", pady=(0, 2))

        self.ev_meta_lbl = ttk.Label(ev_card, text="Status: Awaiting ingestion", style="CardMuted.TLabel")
        self.ev_meta_lbl.pack(anchor="w")

        # --- Section 2: Analysis Cards Grid ---
        grid_frame = ttk.Frame(self._scroll_frame)
        grid_frame.pack(fill="x", pady=(0, 8), **pad)
        grid_frame.columnconfigure(0, weight=1)
        grid_frame.columnconfigure(1, weight=1)

        # ELA Card
        ela_card = ttk.Frame(grid_frame, style="Card.TFrame", padding=16)
        ela_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))

        ttk.Label(ela_card, text="Error Level Analysis (ELA)", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 4))
        self.ela_score_lbl = ttk.Label(ela_card, text="Anomaly Score: Not calculated", style="ScoreHigh.TLabel")
        self.ela_score_lbl.pack(anchor="w", pady=(6, 4))
        self.ela_desc_lbl = ttk.Label(
            ela_card,
            text="Evaluates JPEG compression artifact distribution across the image grid.",
            style="CardMuted.TLabel",
            wraplength=340,
        )
        self.ela_desc_lbl.pack(anchor="w")

        # Deepfake Card
        df_card = ttk.Frame(grid_frame, style="Card.TFrame", padding=16)
        df_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))

        ttk.Label(df_card, text="Synthetic Media Assessment", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 4))
        self.df_score_lbl = ttk.Label(df_card, text="Synthetic Prob: Not calculated", style="ScoreLow.TLabel")
        self.df_score_lbl.pack(anchor="w", pady=(6, 4))
        self.df_desc_lbl = ttk.Label(
            df_card,
            text="Probabilistic assessment of AI manipulation or generative generation.",
            style="CardMuted.TLabel",
            wraplength=340,
        )
        self.df_desc_lbl.pack(anchor="w")

        # Caution Callout
        caution_box = ttk.Frame(self._scroll_frame, style="Card.TFrame", padding=12)
        caution_box.pack(fill="x", pady=(8, 16), **pad)

        caution_lbl = ttk.Label(
            caution_box,
            text="[!] Forensic Caveat & Non-Defamation Rule",
            font=Fonts.SMALL_BOLD,
            foreground=Colors.WARNING,
        )
        caution_lbl.pack(anchor="w", pady=(0, 4))

        caution_text = (
            "All metrics and scores provided by DigitalShield are probabilistic assessments designed "
            "for defensive technical review. They do not constitute absolute legal or forensic proof "
            "of forgery, nor do they determine criminal guilt or individual liability."
        )
        ttk.Label(
            caution_box,
            text=caution_text,
            style="CardMuted.TLabel",
            wraplength=740,
        ).pack(anchor="w")

        # Navigation Action Bar
        btn_bar = ttk.Frame(self._scroll_frame)
        btn_bar.pack(fill="x", pady=(0, 16), **pad)

        ttk.Button(
            btn_bar,
            text="Technical Details",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("details"),
        ).pack(side="left", padx=(0, 8))

        ttk.Button(
            btn_bar,
            text="Provenance & Chain",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("provenance"),
        ).pack(side="left", padx=8)

        ttk.Button(
            btn_bar,
            text="Generate Report",
            style="Primary.TButton",
            command=lambda: self.app.show_screen("reports"),
        ).pack(side="right")

        # --- Section 3: Automatic Reverse Image Search Panel ---
        self._build_reverse_search_panel(self._scroll_frame, pad)

    def _build_reverse_search_panel(self, parent, pad):
        """Build the full-width Automatic Reverse Image Search card."""
        wd_card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        wd_card.pack(fill="x", pady=(0, 16), **pad)

        # Title row
        title_row = ttk.Frame(wd_card, style="Card.TFrame")
        title_row.pack(fill="x", pady=(0, 8))

        ttk.Label(
            title_row,
            text="🔍  Automatic Reverse Image Search",
            style="CardHeading.TLabel",
        ).pack(side="left")

        self._wd_badge_lbl = ttk.Label(
            title_row,
            text="AUTOMATED PIPELINE",
            font=Fonts.SMALL_BOLD,
            foreground=Colors.ACCENT,
        )
        self._wd_badge_lbl.pack(side="right")

        # Metrics overview grid
        self._metrics_frame = ttk.Frame(wd_card, style="Card.TFrame")
        self._metrics_frame.pack(fill="x", pady=(0, 8))

        self._provider_lbl = ttk.Label(
            self._metrics_frame,
            text="Provider: Google Cloud Vision Web Detection",
            style="CardMuted.TLabel",
            font=Fonts.SMALL_BOLD,
        )
        self._provider_lbl.grid(row=0, column=0, sticky="w", padx=(0, 16), pady=2)

        self._status_lbl = ttk.Label(
            self._metrics_frame,
            text="Status: Pending",
            style="CardMuted.TLabel",
            font=Fonts.SMALL_BOLD,
        )
        self._status_lbl.grid(row=0, column=1, sticky="w", padx=(0, 16), pady=2)

        self._counts_lbl = ttk.Label(
            self._metrics_frame,
            text="Candidates: 0 | Verified Matches: 0 | Unverified: 0 | Failed: 0",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._counts_lbl.grid(row=1, column=0, columnspan=2, sticky="w", pady=2)

        self._timing_lbl = ttk.Label(
            self._metrics_frame,
            text="Search Started: N/A | Completed: N/A",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._timing_lbl.grid(row=2, column=0, columnspan=2, sticky="w", pady=2)

        # Limitation notice
        ttk.Label(
            wd_card,
            text=(
                "[!]  Forensic Limitation: Reverse image search results depend on the external provider's indexed "
                "content. DigitalShield cannot guarantee discovery of every online occurrence. Perceptual hash "
                "similarity is an investigative indicator and does not independently prove image identity or unauthorized distribution."
            ),
            style="CardMuted.TLabel",
            foreground=Colors.WARNING,
            wraplength=760,
        ).pack(anchor="w", pady=(4, 8))

        # Separator
        ttk.Separator(wd_card, orient="horizontal").pack(fill="x", pady=(0, 8))

        # Results table container
        table_frame = ttk.Frame(wd_card, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)

        columns = ("platform", "title", "match_type", "similarity", "status", "source_url")
        self._tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=7,
        )

        self._tree.heading("platform", text="Platform")
        self._tree.heading("title", text="Page Title")
        self._tree.heading("match_type", text="Match Type")
        self._tree.heading("similarity", text="Similarity")
        self._tree.heading("status", text="Status")
        self._tree.heading("source_url", text="Source")

        self._tree.column("platform", width=110, anchor="w")
        self._tree.column("title", width=180, anchor="w")
        self._tree.column("match_type", width=110, anchor="w")
        self._tree.column("similarity", width=110, anchor="center")
        self._tree.column("status", width=110, anchor="w")
        self._tree.column("source_url", width=220, anchor="w")

        tree_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=tree_scrollbar.set)

        self._tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar.pack(side="right", fill="y")

        # Double-click or single selection to open link
        self._tree.bind("<Double-1>", self._on_tree_double_click)

        # Action bar under table
        tbl_btn_bar = ttk.Frame(wd_card, style="Card.TFrame")
        tbl_btn_bar.pack(fill="x", pady=(8, 0))

        self._open_sel_btn = ttk.Button(
            tbl_btn_bar,
            text="🔗 Open Selected Source in Browser",
            style="Primary.TButton",
            command=self._open_selected_source,
        )
        self._open_sel_btn.pack(side="left")

        self._lbl_hint = ttk.Label(
            tbl_btn_bar,
            text="Double-click any row to open the discovered webpage directly in your web browser.",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._lbl_hint.pack(side="left", padx=12)

    # ------------------------------------------------ Treeview Interactions --

    def _open_selected_source(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Select Source", "Please select a row from the table to open.")
            return
        item = self._tree.item(sel[0])
        url = item.get("values", [None] * 6)[5]
        if url and url != "N/A":
            webbrowser.open(str(url))

    def _on_tree_double_click(self, event):
        self._open_selected_source()

    # --------------------------------------------------------- Data Loading --

    def load_data(self, data: dict):
        """Populate results from active case data bundle."""
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

            self._evidence_id = eid
            self._load_web_discovery_results(data, eid)
        else:
            self.ev_title_lbl.config(text="Evidence Item: Not available")
            self.ev_hash_lbl.config(text="SHA-256: Not available")
            self.ev_meta_lbl.config(text="Status: No evidence loaded")
            self._evidence_id = None

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

    def _load_web_discovery_results(self, data: dict, evidence_id: str):
        """Populate Reverse Image Search metrics and Treeview table."""
        session = data.get("web_discovery_session")
        results = data.get("web_discovery_results") or []

        # If not present in memory payload, query JSONStore
        if not session and evidence_id:
            sessions = self.wd_service.list_sessions_by_evidence(evidence_id)
            if sessions:
                session = sessions[-1].to_dict()
                results = [r.to_dict() for r in self.wd_service.list_results_by_session(session["session_id"])]

        # Clear existing rows
        for item in self._tree.get_children():
            self._tree.delete(item)

        if not session:
            self._status_lbl.config(text="Status: No search performed", foreground=Colors.TEXT_MUTED)
            self._counts_lbl.config(text="Candidates: 0 | Verified Matches: 0 | Unverified: 0 | Failed: 0")
            self._timing_lbl.config(text="Search Started: N/A | Completed: N/A")
            return

        status = session.get("status", "UNKNOWN")
        provider = session.get("provider", "Google Cloud Vision Web Detection")
        started = (session.get("started_at") or session.get("search_timestamp") or "")[:19]
        completed = (session.get("completed_at") or "")[:19] or "In progress"

        total = session.get("total_results", 0) or session.get("total_candidates", 0)
        verified = session.get("verified_matches", 0)
        unverified = session.get("unverified_results", 0)
        failed = session.get("failed_sources", 0)

        # Status text styling
        status_fg = Colors.SUCCESS if status == "COMPLETED" else (
            Colors.WARNING if status in ("NO_RESULTS", "MISSING_CREDENTIALS") else Colors.DANGER
        )
        if status == "MISSING_CREDENTIALS":
            status_text = "Status: Provider Unavailable (Missing GOOGLE_CLOUD_API_KEY)"
        elif status == "FAILED":
            err = session.get("error_message") or "Provider execution error"
            status_text = f"Status: Failed ({err[:50]})"
        else:
            status_text = f"Status: {status}"

        self._provider_lbl.config(text=f"Provider: {provider}")
        self._status_lbl.config(text=status_text, foreground=status_fg)
        self._counts_lbl.config(
            text=f"Candidates: {total} | Verified Matches: {verified} | Unverified: {unverified} | Failed: {failed}"
        )
        self._timing_lbl.config(text=f"Search Started: {started} UTC | Completed: {completed} UTC")

        # Insert rows into Treeview
        for r in results:
            platform = r.get("platform") or r.get("domain") or "Web Source"
            title = r.get("page_title") or "Not available"
            mtype = r.get("provider_match_type") or "SIMILAR"
            
            # Format similarity percentage if calculated
            calc_sim = r.get("calculated_similarity") or r.get("independent_similarity_score")
            sim_str = f"{calc_sim * 100:.1f}%" if calc_sim is not None else "Unverified"

            vstatus = r.get("verification_status") or r.get("status") or "Discovered"
            surl = r.get("source_url") or "N/A"

            self._tree.insert(
                "",
                "end",
                values=(platform, title[:30], mtype, sim_str, vstatus, surl),
            )
