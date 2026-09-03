import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

from digitalshield.gui.theme import Colors, Fonts
from digitalshield.security.audit import AuditLogger


def _get_val(obj: Any, key: str, default: Any = None) -> Any:
    """Safely get a value from either a Pydantic model or a dictionary."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


class DetailsScreen(ttk.Frame):
    """
    Tabbed view providing comprehensive technical breakdowns across all modules.
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

        title = ttk.Label(header, text="Detailed Technical Inspection", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Notebook (Tabs)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=24, pady=(0, 20))

        # Tab 1: Overview
        self.overview_tab = self._create_scrollable_tab("Case & Evidence")
        # Tab 2: Metadata / EXIF
        self.meta_tab = self._create_scrollable_tab("Technical & EXIF")
        # Tab 3: Fingerprints
        self.fp_tab = self._create_scrollable_tab("Perceptual Hashes")
        # Tab 4: ELA
        self.ela_tab = self._create_scrollable_tab("Error Level Analysis")
        # Tab 5: Deepfake
        self.df_tab = self._create_scrollable_tab("Synthetic Media")
        # Tab 6: Audit Log
        self.audit_tab = self._create_scrollable_tab("Audit Trail")

    def _create_scrollable_tab(self, label: str) -> ttk.Frame:
        tab_frame = ttk.Frame(self.notebook, padding=16)
        self.notebook.add(tab_frame, text=label)
        
        # Scrolled text area for clean read-only formatting
        text_widget = tk.Text(
            tab_frame,
            wrap="word",
            font=Fonts.MONO,
            bg=Colors.CARD_BG,
            fg=Colors.TEXT_MAIN,
            relief="solid",
            borderwidth=1,
            padx=14,
            pady=14,
        )
        scrollbar = ttk.Scrollbar(tab_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        text_widget.pack(side="left", fill="both", expand=True)
        tab_frame.text_widget = text_widget
        return tab_frame

    def load_data(self, data: dict):
        """Populate all tab contents from active case data."""
        if not data:
            data = {}

        case = data.get("case")
        ev = data.get("evidence")
        meta = data.get("metadata")
        fp = data.get("fingerprints")
        ela = data.get("ela")
        df = data.get("deepfake")

        # 1. Overview Tab
        t1 = self.overview_tab.text_widget
        t1.config(state="normal")
        t1.delete("1.0", "end")
        t1.insert("end", "=== CASE & EVIDENCE OVERVIEW ===\n\n")
        if case:
            cid = _get_val(case, "case_id", "Not available")
            cname = _get_val(case, "name", "Not available")
            inv = _get_val(case, "investigator", "Not available")
            status = _get_val(case, "status", "Not available")
            cat = _get_val(case, "created_at", "Not available")

            t1.insert("end", f"Case ID:             {cid}\n")
            t1.insert("end", f"Case Name:           {cname}\n")
            t1.insert("end", f"Investigator:        {inv}\n")
            t1.insert("end", f"Status:              {status}\n")
            t1.insert("end", f"Created At (UTC):    {cat}\n\n")
        else:
            t1.insert("end", "Case details:        Not available\n\n")

        if ev:
            eid = _get_val(ev, "evidence_id", "Not available")
            fname = _get_val(ev, "original_filename", "Not available")
            spath = _get_val(ev, "stored_path", "Not available")
            fsize = _get_val(ev, "file_size", 0)
            mime = _get_val(ev, "mime_type", "Not available")
            its = _get_val(ev, "import_timestamp", "Not available")
            sha = _get_val(ev, "sha256", "Not available")

            t1.insert("end", f"Evidence ID:         {eid}\n")
            t1.insert("end", f"Original Filename:   {fname}\n")
            t1.insert("end", f"Stored Vault Copy:   {spath}\n")
            t1.insert("end", f"File Size:           {fsize:,} bytes\n")
            t1.insert("end", f"MIME Type:           {mime}\n")
            t1.insert("end", f"Import Time (UTC):   {its}\n")
            t1.insert("end", f"Preserved SHA-256:   {sha}\n")
        else:
            t1.insert("end", "Evidence details:    Not available\n")
        t1.config(state="disabled")

        # 2. Metadata Tab
        t2 = self.meta_tab.text_widget
        t2.config(state="normal")
        t2.delete("1.0", "end")
        t2.insert("end", "=== TECHNICAL & EXIF METADATA ===\n\n")
        if meta:
            w = _get_val(meta, "width_px", "N/A")
            h = _get_val(meta, "height_px", "N/A")
            cmode = _get_val(meta, "color_mode", "N/A")
            ffmt = _get_val(meta, "file_format", "N/A")
            exif_p = _get_val(meta, "exif_present", False)
            make = _get_val(meta, "camera_make") or "Not recorded"
            model = _get_val(meta, "camera_model") or "Not recorded"
            sw = _get_val(meta, "software") or "Not recorded"
            dt_orig = _get_val(meta, "datetime_original") or "Not recorded"
            gps_lat = _get_val(meta, "gps_latitude") or "N/A"
            gps_lon = _get_val(meta, "gps_longitude") or "N/A"

            t2.insert("end", f"Dimensions:          {w} x {h} px\n")
            t2.insert("end", f"Color Mode:          {cmode}\n")
            t2.insert("end", f"File Format:         {ffmt}\n")
            t2.insert("end", f"EXIF Present:        {exif_p}\n")
            t2.insert("end", f"Camera Make:         {make}\n")
            t2.insert("end", f"Camera Model:        {model}\n")
            t2.insert("end", f"Software:            {sw}\n")
            t2.insert("end", f"Original DateTime:   {dt_orig}\n")
            t2.insert("end", f"GPS Coordinates:     Lat: {gps_lat}, Lon: {gps_lon}\n\n")
            t2.insert("end", "> Note: Absence of EXIF metadata is standard across messaging applications and social media.\n")
        else:
            t2.insert("end", "No metadata record available.\n")
        t2.config(state="disabled")

        # 3. Fingerprints Tab
        t3 = self.fp_tab.text_widget
        t3.config(state="normal")
        t3.delete("1.0", "end")
        t3.insert("end", "=== PERCEPTUAL HASHES (64-BIT STRUCTURAL FINGERPRINTS) ===\n\n")
        if fp:
            ah = _get_val(fp, "ahash", "N/A")
            dh = _get_val(fp, "dhash", "N/A")
            ph = _get_val(fp, "phash", "N/A")

            t3.insert("end", f"aHash (Average):     {ah}\n")
            t3.insert("end", f"dHash (Difference):  {dh}\n")
            t3.insert("end", f"pHash (Perceptual):  {ph}\n\n")
            t3.insert("end", "Perceptual hashes remain invariant under slight resizing and compression changes.\n")
            t3.insert("end", "Disclaimer: Perceptual similarity is an investigative indicator and does not prove ownership or authorship.\n")
        else:
            t3.insert("end", "No fingerprint record available.\n")
        t3.config(state="disabled")

        # 4. ELA Tab
        t4 = self.ela_tab.text_widget
        t4.config(state="normal")
        t4.delete("1.0", "end")
        t4.insert("end", "=== ERROR LEVEL ANALYSIS (ELA) ===\n\n")
        if ela:
            qual = _get_val(ela, "recompression_quality", 90)
            mean_e = _get_val(ela, "mean_error", 0.0)
            max_e = _get_val(ela, "max_error", 0.0)
            stats = _get_val(ela, "statistics", {})
            stddev_e = _get_val(stats, "stddev_error", 0.0)
            high_px = _get_val(stats, "high_error_pixels", 0)
            high_ratio = _get_val(stats, "high_error_ratio", 0.0)
            score = _get_val(ela, "anomaly_score", 0.0)
            conf = _get_val(ela, "confidence", 0.0)
            assess = _get_val(ela, "assessment", "Not available")
            disclaimer = _get_val(ela, "disclaimer", "Not available")

            t4.insert("end", f"Recompression Level: {qual}%\n")
            t4.insert("end", f"Mean Error Level:    {mean_e:.4f}\n")
            t4.insert("end", f"Maximum Error Level: {max_e:.4f}\n")
            t4.insert("end", f"Standard Deviation:  {stddev_e:.4f}\n")
            t4.insert("end", f"High Error Pixels:   {high_px:,} ({high_ratio*100:.2f}%)\n")
            t4.insert("end", f"Anomaly Score:       {score:.4f}\n")
            t4.insert("end", f"Confidence:          {conf*100:.1f}%\n\n")
            t4.insert("end", f"Assessment:\n{assess}\n\n")
            t4.insert("end", f"Limitations & Disclaimer:\n{disclaimer}\n")
        else:
            t4.insert("end", "No ELA record available.\n")
        t4.config(state="disabled")

        # 5. Deepfake Tab
        t5 = self.df_tab.text_widget
        t5.config(state="normal")
        t5.delete("1.0", "end")
        t5.insert("end", "=== AI-ASSISTED SYNTHETIC MEDIA ASSESSMENT ===\n\n")
        if df:
            dname = _get_val(df, "detector_name", "Unknown")
            dtype = _get_val(df, "detector_type", "Unknown")
            prob = _get_val(df, "synthetic_probability", 0.0)
            conf = _get_val(df, "confidence", 0.0)
            assess = _get_val(df, "assessment", "Not available")
            indicators = _get_val(df, "indicators", []) or []
            features = _get_val(df, "features_used", []) or []
            limitations = _get_val(df, "limitations", []) or []

            t5.insert("end", f"Detector:            {dname} ({dtype})\n")
            t5.insert("end", f"Synthetic Prob:      {prob:.2f} (0.00 to 1.00)\n")
            t5.insert("end", f"Confidence:          {conf*100:.1f}%\n\n")
            t5.insert("end", f"Assessment Summary:\n{assess}\n\n")
            t5.insert("end", "Observed Indicators:\n")
            if indicators:
                for ind in indicators:
                    t5.insert("end", f"  • {ind}\n")
            else:
                t5.insert("end", "  • None reported\n")

            t5.insert("end", "\nEvaluated Features:\n")
            if features:
                for feat in features:
                    t5.insert("end", f"  • {feat}\n")
            else:
                t5.insert("end", "  • None reported\n")

            t5.insert("end", "\nOperational Caveats & Limitations:\n")
            if limitations:
                for lim in limitations:
                    t5.insert("end", f"  • {lim}\n")
            else:
                t5.insert("end", "  • Standard forensic limitations apply.\n")
        else:
            t5.insert("end", "No deepfake assessment record available.\n")
        t5.config(state="disabled")

        # 6. Audit Tab
        t6 = self.audit_tab.text_widget
        t6.config(state="normal")
        t6.delete("1.0", "end")
        t6.insert("end", "=== CASE AUDIT TRAIL & CHAIN OF CUSTODY ===\n\n")
        if case:
            cid = _get_val(case, "case_id")
            log_path = (self.app.base_dir / "audit.log") if self.app.base_dir else None
            audit_logger = AuditLogger(log_path=log_path)
            events = audit_logger.get_events_by_case(cid) if cid else []
            if events:
                for e in events:
                    ts = e.get("timestamp", "")[:19]
                    act = e.get("action", "")
                    actor = e.get("actor", "")
                    ehash = e.get("entry_hash", "")[:16] + "..." if e.get("entry_hash") else "N/A"
                    t6.insert("end", f"[{ts}] {act:<30} Actor: {actor:<20} Hash: {ehash}\n")
            else:
                t6.insert("end", "No case-specific audit entries found.\n")
        else:
            t6.insert("end", "No active case selected.\n")
        t6.config(state="disabled")
