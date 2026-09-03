# DigitalShield Forensic Reporting Subsystem (Phase 8)

## 1. Overview & Objectives
The **DigitalShield Reporting Subsystem** provides standardized, reproducible, and verifiable forensic report generation. It aggregates case parameters, cryptographic evidence baselines, technical and EXIF metadata, perceptual hash comparisons, Error Level Analysis (ELA) manipulation metrics, AI-assisted deepfake assessments, public URL provenance observations, propagation timelines, and append-only audit chains into comprehensive, reviewable documents.

Reports are generated strictly locally in three interoperable formats:
1. **Markdown (.md)**: Lightweight, version-controllable, GitHub-flavored format.
2. **HTML (.html)**: Fully self-contained local web document with embedded styles, print stylesheets, and zero remote dependencies or tracking.
3. **PDF (.pdf)**: Printable, paginated document with dynamic running headers, footers, and page numbers.

---

## 2. Architecture & Data Flow

`
digitalshield/reporting/
├── models.py                # ReportData, ReportMetadata, ReportRecord models
├── renderers/
│   ├── markdown_renderer.py # Clean GitHub Flavored Markdown renderer
│   ├── html_renderer.py     # Standalone local HTML renderer (100% offline)
│   └── pdf_renderer.py      # Paginated ReportLab PDF renderer
└── service.py               # ReportingService coordinating aggregation, persistence, & audit logging
`

All format renderers receive a unified ReportData object, guaranteeing 100% data parity and preventing divergent logic across formats.

---

## 3. Storage Layout
Generated reports are stored within the standard case container:

`
.digitalshield_data/
└── cases/
    └── <case_id>/
        ├── evidence/        # Preserved read-only evidence vault
        ├── analysis/        # Derived analysis JSON files
        └── reports/         # Local generated reports
            ├── report_RPT-2026-000001.md
            ├── report_RPT-2026-000001.html
            └── report_RPT-2026-000001.pdf
`

Report metadata and file paths are indexed centrally in .digitalshield_data/reports.json.

---

## 4. Forensic & Ethical Safeguards

1. **Evidence Immutability**: All operations read preserved evidence files without modification. SHA-256 digests represent the baseline vault copies.
2. **Zero Information Fabrication**: Unavailable metadata fields, timestamps, usernames, or analysis scores are explicitly noted as Not recorded or None. Values are never guessed.
3. **Probabilistic AI & ELA Labeling**: AI-assisted synthetic media and ELA findings are prominently marked with warning banners and probabilistic disclaimers. The report never asserts certainty of deepfake manipulation or forgery.
4. **Neutral Attributions**: Public source observations use neutral investigative terminology (*Reported source*, *Observed account*, *Investigative lead*, *Evidence-supported association*). Reports never infer criminal responsibility, ownership, or guilt.
5. **SSRF & Offline Privacy**: HTML and PDF generation run 100% locally with zero external network calls, remote CDNs, or telemetry.

---

## 5. CLI Usage & Commands

### Generate Forensic Report
Generate all formats (Markdown, HTML, PDF) by default:
`ash
python -m digitalshield report generate DS-2026-000001
`

Generate a specific format:
`ash
python -m digitalshield report generate DS-2026-000001 --format markdown
python -m digitalshield report generate DS-2026-000001 --format html
python -m digitalshield report generate DS-2026-000001 --format pdf
python -m digitalshield report generate DS-2026-000001 --format all
`

### List Case Reports
List all reports generated for a case:
`ash
python -m digitalshield report list --case DS-2026-000001
`

### Show Report Details
Inspect file paths and generation status of a specific report ID:
`ash
python -m digitalshield report show RPT-2026-000001
`

---

## 6. Audit Trail Integration
Every report generation event is recorded in the append-only, SHA-256 hashed audit log:
- **Action**: REPORT_GENERATED
- **Details**: 
eport_id, case_id, ormats, iles
- **Actor**: DigitalShield Reporting Engine
