"""
Results Summary Screen presenting high-level forensic findings.

Includes the full-width Automatic Reverse Image Search section with:
- Platform filter tabs (All / X / Reddit / Instagram / Facebook / YouTube / TikTok /
  Pinterest / Wikipedia / Other Websites)
- Result cards showing platform, source type, page title, similarity score,
  verification status, and clickable links to the original page and image.
"""

import tkinter as tk
import webbrowser
from collections import defaultdict
from tkinter import messagebox, ttk
from typing import Any, Dict, List, Optional

from digitalshield.gui.theme import Colors, Fonts
from digitalshield.web_discovery.service import WebDiscoveryService

# Platform tabs shown in the filter bar (order matters)
PLATFORM_TABS = [
    "All Results",
    "X (Twitter)",
    "Reddit",
    "Instagram",
    "Facebook",
    "YouTube",
    "TikTok",
    "Pinterest",
    "Wikipedia",
    "Other Websites",
]

# Platforms that map to "Other Websites" in the filter
_KNOWN_SOCIAL = {
    "X (Twitter)", "Reddit", "Instagram", "Facebook",
    "YouTube", "TikTok", "Pinterest", "Wikipedia",
}

# Small Unicode icons for each platform tab
PLATFORM_ICONS = {
    "All Results":   "🔍",
    "X (Twitter)":  "𝕏",
    "Reddit":        "🤖",
    "Instagram":     "📷",
    "Facebook":      "👤",
    "YouTube":       "▶",
    "TikTok":        "🎵",
    "Pinterest":     "📌",
    "Wikipedia":     "📖",
    "Other Websites": "🌐",
}


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get a value from either a Pydantic model or a dictionary."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _platform_tab_for(platform: str) -> str:
    """Map a platform name to one of the PLATFORM_TABS filter categories."""
    if not platform:
        return "Other Websites"
    if platform in _KNOWN_SOCIAL:
        return platform
    if platform == "Google (Thumbnail Cache)":
        return "Other Websites"
    return "Other Websites"


class ResultsScreen(ttk.Frame):
    """
    Displays summary findings, indicator scores, and report generation triggers.
    Includes the Automatic Reverse Image Search & Public Web Discovery findings panel.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._evidence_id: Optional[str] = None
        self._wd_service: Optional[WebDiscoveryService] = None
        self._all_results: List[Dict] = []
        self._active_tab: str = "All Results"
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
        """Build the full-width Automatic Reverse Image Search card with platform tabs."""
        wd_card = ttk.Frame(parent, style="Card.TFrame", padding=16)
        wd_card.pack(fill="x", pady=(0, 16), **pad)

        # Title row
        title_row = ttk.Frame(wd_card, style="Card.TFrame")
        title_row.pack(fill="x", pady=(0, 8))

        ttk.Label(
            title_row,
            text="🔍  Automatic Reverse Image Search — Social Media & Public Website Sources",
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
            text="Provider: Google Lens",
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

        self._platform_summary_lbl = ttk.Label(
            self._metrics_frame,
            text="Platforms: —",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._platform_summary_lbl.grid(row=2, column=0, columnspan=2, sticky="w", pady=2)

        self._timing_lbl = ttk.Label(
            self._metrics_frame,
            text="Search Started: N/A | Completed: N/A",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._timing_lbl.grid(row=3, column=0, columnspan=2, sticky="w", pady=2)

        # Limitation notice
        ttk.Label(
            wd_card,
            text=(
                "[!]  Forensic Limitation: Results depend on the external provider's indexed content. "
                "Google thumbnail cache URLs (encrypted-tbn*.gstatic.com) are labeled separately and "
                "are NOT the original publishing website. Platform names identify hosting sites, not "
                "the identity of the person who uploaded the content."
            ),
            style="CardMuted.TLabel",
            foreground=Colors.WARNING,
            wraplength=760,
        ).pack(anchor="w", pady=(4, 8))

        ttk.Separator(wd_card, orient="horizontal").pack(fill="x", pady=(0, 6))

        # --- Platform Filter Tabs ---
        tab_frame = ttk.Frame(wd_card, style="Card.TFrame")
        tab_frame.pack(fill="x", pady=(0, 8))

        self._tab_buttons: Dict[str, ttk.Button] = {}
        self._tab_count_labels: Dict[str, ttk.Label] = {}

        for tab_name in PLATFORM_TABS:
            icon = PLATFORM_ICONS.get(tab_name, "")
            col_frame = ttk.Frame(tab_frame, style="Card.TFrame")
            col_frame.pack(side="left", padx=(0, 4))

            btn = ttk.Button(
                col_frame,
                text=f"{icon} {tab_name}",
                style="Outline.TButton",
                command=lambda t=tab_name: self._filter_by_platform(t),
            )
            btn.pack()

            cnt_lbl = ttk.Label(col_frame, text="(0)", style="CardMuted.TLabel", font=Fonts.SMALL)
            cnt_lbl.pack()

            self._tab_buttons[tab_name] = btn
            self._tab_count_labels[tab_name] = cnt_lbl

        ttk.Separator(wd_card, orient="horizontal").pack(fill="x", pady=(0, 6))

        # Results table
        table_frame = ttk.Frame(wd_card, style="Card.TFrame")
        table_frame.pack(fill="both", expand=True)

        columns = ("platform", "source_type", "title", "similarity", "status", "source_url", "image_url")
        self._tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            height=8,
        )

        self._tree.heading("platform",    text="Platform")
        self._tree.heading("source_type", text="Source Type")
        self._tree.heading("title",       text="Page Title")
        self._tree.heading("similarity",  text="Similarity")
        self._tree.heading("status",      text="Verification")
        self._tree.heading("source_url",  text="Webpage URL")
        self._tree.heading("image_url",   text="Image URL")

        self._tree.column("platform",    width=110, anchor="w")
        self._tree.column("source_type", width=130, anchor="w")
        self._tree.column("title",       width=160, anchor="w")
        self._tree.column("similarity",  width=80,  anchor="center")
        self._tree.column("status",      width=120, anchor="w")
        self._tree.column("source_url",  width=200, anchor="w")
        self._tree.column("image_url",   width=160, anchor="w")

        tree_scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=tree_scrollbar.set)

        self._tree.pack(side="left", fill="both", expand=True)
        tree_scrollbar.pack(side="right", fill="y")

        # Tag for Google thumbnail rows — shown in muted colour
        self._tree.tag_configure("gthumbnail", foreground="#94a3b8")

        # Double-click to open source URL
        self._tree.bind("<Double-1>", self._on_tree_double_click)

        # Action bar
        tbl_btn_bar = ttk.Frame(wd_card, style="Card.TFrame")
        tbl_btn_bar.pack(fill="x", pady=(8, 0))

        self._open_page_btn = ttk.Button(
            tbl_btn_bar,
            text="🔗 Open Webpage in Browser",
            style="Primary.TButton",
            command=self._open_selected_source,
        )
        self._open_page_btn.pack(side="left")

        self._open_img_btn = ttk.Button(
            tbl_btn_bar,
            text="🖼 Open Image URL",
            style="Outline.TButton",
            command=self._open_selected_image,
        )
        self._open_img_btn.pack(side="left", padx=(8, 0))

        self._lbl_hint = ttk.Label(
            tbl_btn_bar,
            text="Double-click any row to open the source webpage. Use buttons to open page or image separately.",
            style="CardMuted.TLabel",
            font=Fonts.SMALL,
        )
        self._lbl_hint.pack(side="left", padx=12)

    # ------------------------------------------- Platform Filtering --

    def _filter_by_platform(self, tab_name: str):
        """Filter displayed results to the chosen platform tab."""
        self._active_tab = tab_name
        self._populate_tree(self._all_results)

    def _populate_tree(self, results: List[Dict]):
        """Clear and refill the Treeview based on active platform tab."""
        for item in self._tree.get_children():
            self._tree.delete(item)

        for r in results:
            platform = r.get("platform") or r.get("domain") or "Web Source"
            tab = _platform_tab_for(platform)

            if self._active_tab != "All Results" and tab != self._active_tab:
                continue

            source_type = r.get("source_type") or "Public Website"
            title = r.get("page_title") or r.get("og_title") or "Not available"
            calc_sim = r.get("calculated_similarity") or r.get("independent_similarity_score")
            sim_str = f"{calc_sim * 100:.1f}%" if calc_sim is not None else "Unverified"
            vstatus = r.get("verification_status") or "Discovered"
            surl = r.get("source_url") or "N/A"
            img_url = r.get("media_url") or r.get("og_image") or r.get("thumbnail_url") or "N/A"

            is_gthumbnail = r.get("is_google_thumbnail", False)
            tags = ("gthumbnail",) if is_gthumbnail else ()

            self._tree.insert(
                "",
                "end",
                values=(
                    platform,
                    source_type[:24],
                    title[:35],
                    sim_str,
                    vstatus[:30],
                    surl,
                    img_url,
                ),
                tags=tags,
            )

    def _update_tab_counts(self, results: List[Dict]):
        """Update the count label beneath each platform tab."""
        tab_counts: Dict[str, int] = defaultdict(int)
        for r in results:
            platform = r.get("platform") or r.get("domain") or "Web Source"
            tab = _platform_tab_for(platform)
            tab_counts["All Results"] += 1
            tab_counts[tab] += 1

        for tab_name in PLATFORM_TABS:
            cnt = tab_counts.get(tab_name, 0)
            self._tab_count_labels[tab_name].config(text=f"({cnt})")

    # ------------------------------------------ Treeview Interactions --

    def _selected_values(self):
        sel = self._tree.selection()
        if not sel:
            return None
        return self._tree.item(sel[0]).get("values", [])

    def _open_selected_source(self):
        vals = self._selected_values()
        if not vals:
            messagebox.showinfo("Select Source", "Please select a row from the table first.")
            return
        url = vals[5] if len(vals) > 5 else None
        if url and url != "N/A":
            webbrowser.open(str(url))
        else:
            messagebox.showinfo("No URL", "The selected row does not have a webpage URL.")

    def _open_selected_image(self):
        vals = self._selected_values()
        if not vals:
            messagebox.showinfo("Select Source", "Please select a row from the table first.")
            return
        url = vals[6] if len(vals) > 6 else None
        if url and url != "N/A":
            webbrowser.open(str(url))
        else:
            messagebox.showinfo("No Image URL", "The selected row does not have an image URL.")

    def _on_tree_double_click(self, event):
        self._open_selected_source()

    # --------------------------------------------------------- Data Loading --

    def load_data(self, data: dict):
        """Populate results from active case data bundle."""
        if not data:
            data = {}

        ev  = data.get("evidence")
        ela = data.get("ela")
        df  = data.get("deepfake")

        if ev:
            fname  = _get_val(ev, "original_filename", "Unknown")
            eid    = _get_val(ev, "evidence_id", "Unknown")
            sha    = _get_val(ev, "sha256", "Not available")
            fsize  = _get_val(ev, "file_size", 0)
            mime   = _get_val(ev, "mime_type", "Unknown")
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
            conf  = _get_val(ela, "confidence")
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
            prob   = _get_val(df, "synthetic_probability")
            conf   = _get_val(df, "confidence")
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
        """Populate Reverse Image Search metrics and the results Treeview."""
        session = data.get("web_discovery_session")
        results = data.get("web_discovery_results") or []

        # If not in memory payload, query JSONStore
        if not session and evidence_id:
            sessions = self.wd_service.list_sessions_by_evidence(evidence_id)
            if sessions:
                session = sessions[-1].to_dict()
                results = [r.to_dict() for r in self.wd_service.list_results_by_session(session["session_id"])]

        # Reset
        self._all_results = []
        for item in self._tree.get_children():
            self._tree.delete(item)

        if not session:
            self._status_lbl.config(text="Status: No search performed", foreground=Colors.TEXT_MUTED)
            self._counts_lbl.config(text="Candidates: 0 | Verified Matches: 0 | Unverified: 0 | Failed: 0")
            self._platform_summary_lbl.config(text="Platforms: —")
            self._timing_lbl.config(text="Search Started: N/A | Completed: N/A")
            self._update_tab_counts([])
            return

        status   = session.get("status", "UNKNOWN")
        provider = session.get("provider", "Google Lens")
        started  = (session.get("started_at") or session.get("search_timestamp") or "")[:19]
        completed = (session.get("completed_at") or "")[:19] or "In progress"

        total    = session.get("total_results", 0) or session.get("total_candidates", 0)
        verified = session.get("verified_matches", 0)
        unverified = session.get("unverified_results", 0)
        failed   = session.get("failed_sources", 0)

        # Platform breakdown
        pcounts: Dict[str, int] = session.get("platform_counts") or {}
        distinct = session.get("distinct_platforms", len(pcounts))
        if pcounts:
            top_platforms = sorted(pcounts.items(), key=lambda x: -x[1])[:5]
            plat_str = "  |  ".join(f"{p}: {c}" for p, c in top_platforms)
            if len(pcounts) > 5:
                plat_str += f"  |  +{len(pcounts) - 5} more"
            platform_text = f"Platforms found ({distinct}): {plat_str}"
        else:
            platform_text = f"Platforms: {distinct} distinct"

        # Status text styling
        status_fg = Colors.SUCCESS if status == "COMPLETED" else (
            Colors.WARNING if status in ("NO_RESULTS", "MISSING_CREDENTIALS", "PROVIDER_UNAVAILABLE") else Colors.DANGER
        )
        if status in ("MISSING_CREDENTIALS", "PROVIDER_UNAVAILABLE"):
            err = session.get("error_message") or "Provider credentials or gateway unavailable"
            status_text = f"Status: Provider Unavailable ({err[:45]})"
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
        self._platform_summary_lbl.config(text=platform_text)
        self._timing_lbl.config(text=f"Search Started: {started} UTC | Completed: {completed} UTC")

        # Store and render results
        self._all_results = [r if isinstance(r, dict) else r.to_dict() for r in results]
        self._active_tab = "All Results"
        self._update_tab_counts(self._all_results)
        self._populate_tree(self._all_results)
