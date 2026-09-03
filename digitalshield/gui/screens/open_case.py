"""
Open Existing Case Screen listing saved cases from JSONStore.
"""

import os
from pathlib import Path
import tkinter as tk
from tkinter import messagebox, ttk

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.storage.json_store import JSONStore
from digitalshield.gui.theme import Colors, Fonts


class OpenCaseScreen(ttk.Frame):
    """
    Lists existing investigations from JSONStore and allows loading case data into the viewer.
    """

    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self._build_ui()

    def _build_ui(self):
        # Header
        header = ttk.Frame(self, padding=(24, 16))
        header.pack(fill="x")

        back_btn = ttk.Button(
            header,
            text="← Back to Home",
            style="Outline.TButton",
            command=lambda: self.app.show_screen("home"),
        )
        back_btn.pack(side="left")

        title = ttk.Label(header, text="Open Existing Investigation", style="Heading.TLabel")
        title.pack(side="left", padx=15)

        # Content
        content = ttk.Frame(self, padding=24)
        content.pack(fill="both", expand=True)

        card = ttk.Frame(content, style="Card.TFrame", padding=16)
        card.pack(fill="both", expand=True, pady=(0, 16))

        ttk.Label(card, text="Registered Cases in Local Storage", style="CardHeading.TLabel").pack(anchor="w", pady=(0, 10))

        # Case Treeview
        tree_frame = ttk.Frame(card, style="Card.TFrame")
        tree_frame.pack(fill="both", expand=True, pady=(0, 16))

        columns = ("case_id", "name", "investigator", "evidence_count", "created_at")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        
        self.tree.heading("case_id", text="Case ID")
        self.tree.heading("name", text="Case Name")
        self.tree.heading("investigator", text="Lead Investigator")
        self.tree.heading("evidence_count", text="Evidence Count")
        self.tree.heading("created_at", text="Created At (UTC)")

        self.tree.column("case_id", width=120, anchor="center")
        self.tree.column("name", width=220, anchor="w")
        self.tree.column("investigator", width=160, anchor="w")
        self.tree.column("evidence_count", width=100, anchor="center")
        self.tree.column("created_at", width=160, anchor="center")

        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)

        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        # Buttons
        btn_bar = ttk.Frame(card, style="Card.TFrame")
        btn_bar.pack(fill="x")

        refresh_btn = ttk.Button(
            btn_bar,
            text="🔄 Refresh List",
            style="Outline.TButton",
            command=self.refresh_cases,
        )
        refresh_btn.pack(side="left")

        open_btn = ttk.Button(
            btn_bar,
            text="📂 Open Selected Investigation",
            style="Primary.TButton",
            command=self._open_selected,
        )
        open_btn.pack(side="right")

    def refresh_cases(self):
        """Fetch cases from CaseManager."""
        for item in self.tree.get_children():
            self.tree.delete(item)

        case_mgr = CaseManager()
        ev_mgr = EvidenceManager()
        cases = case_mgr.list_cases()

        for c in reversed(cases):
            ev_list = ev_mgr.list_evidence(c.case_id)
            ts = c.created_at[:19].replace("T", " ")
            self.tree.insert(
                "",
                "end",
                iid=c.case_id,
                values=(c.case_id, c.name, c.investigator, len(ev_list), ts),
            )

    def _open_selected(self):
        """Load selected case data from JSONStore and open results view."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Selection Required", "Please select a case from the list to open.")
            return

        case_id = sel[0]
        case_mgr = CaseManager()
        ev_mgr = EvidenceManager()
        store = JSONStore()

        case = case_mgr.get_case(case_id)
        if not case:
            messagebox.showerror("Error", f"Case {case_id} not found.")
            return

        evidence_items = ev_mgr.list_evidence(case_id)
        ev = evidence_items[0] if evidence_items else None

        # Load available derived analysis records from JSONStore
        meta = store.get_metadata(ev.evidence_id) if ev else None
        fp = store.get_fingerprints(ev.evidence_id) if ev else None
        ela = store.get_ela(ev.evidence_id) if ev else None
        df = store.get_deepfake(ev.evidence_id) if ev else None

        # Save to app state
        self.app.case_data = {
            "case": case,
            "evidence": ev,
            "metadata": meta,
            "fingerprints": fp,
            "ela": ela,
            "deepfake": df,
        }

        # Show results screen
        self.app.show_screen("results")
