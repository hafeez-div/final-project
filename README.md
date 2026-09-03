# DigitalShield

> **Defensive Digital Forensics, Evidence Preservation & Forensic Report Generation Suite**

DigitalShield is an academic final-year project designed for **defensive digital forensics**, evidence integrity verification, media manipulation detection, public provenance analysis, and professional forensic report generation. It provides a complete CLI-based forensic workflow suitable for academic demonstration, research, and coursework.

---

## Features at a Glance

| Phase | Feature | Status |
|:---:|:---|:---:|
| 1 | Case Management | ✅ Complete |
| 2 | Evidence Ingestion & SHA-256 Vault | ✅ Complete |
| 3 | Technical Metadata & EXIF Extraction | ✅ Complete |
| 4 | Perceptual Hashing & Similarity Matching | ✅ Complete |
| 5 | Error Level Analysis (ELA) Manipulation Detection | ✅ Complete |
| 6 | AI-Based Deepfake / Synthetic Media Assessment | ✅ Complete |
| 7 | Public URL Provenance Analysis | ✅ Complete |
| 8 | Forensic Report Generation (Markdown / HTML / PDF) | ✅ Complete |

**Test Coverage:** 90 tests — 90 passed, 0 failed, 0 errors.

---

## Architecture & Project Structure

```
DigitalShield/
├── digitalshield/
│   ├── cli/             # CLI entrypoints — case, evidence, analyze, provenance, report
│   ├── case_manager/    # Case lifecycle — create, list, close, reopen
│   ├── evidence/        # Evidence ingestion, SHA-256 read-only vaulting
│   ├── metadata/        # EXIF metadata and GPS extraction
│   ├── fingerprinting/  # aHash, dHash, pHash perceptual fingerprinting
│   ├── detection/       # ELA image manipulation analysis
│   ├── deepfake/        # AI-assisted synthetic media assessment
│   ├── provenance/      # Public URL provenance (SSRF-protected)
│   ├── reporting/       # Forensic report generation (MD, HTML, PDF)
│   │   ├── models.py        # Unified data models for all report formats
│   │   ├── service.py       # Report compilation and persistence service
│   │   └── renderers/
│   │       ├── markdown_renderer.py
│   │       ├── html_renderer.py
│   │       └── pdf_renderer.py
│   ├── storage/         # JSON-based local data persistence (JSONStore)
│   └── security/        # Append-only tamper-evident audit logging
├── tests/               # Full test suite (unit + integration + CLI)
├── docs/                # Architecture, reporting, and design documentation
├── PROJECT_SPEC.md      # Functional requirements specification
└── AGENTS.md            # Strict ethical and development guidelines
```

---

## Installation & Setup

Requires **Python 3.11+**.

```bash
# 1. Clone the repository
git clone https://github.com/example/DigitalShield.git
cd DigitalShield

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

# 3. Install the project and all dependencies
pip install -e .[dev]
```

### Dependencies Installed
- `click` — CLI framework
- `rich` — Terminal formatting
- `Pillow` — Image processing
- `imagehash` — Perceptual hashing (aHash, dHash, pHash)
- `reportlab` — PDF generation
- `requests` — HTTP client for provenance analysis
- `pytest` — Test framework

---

## Running the Test Suite

```bash
pytest
```

**Expected result:** `96 passed, 0 failed`

---

## Desktop Graphical Interface (GUI)

DigitalShield provides a clean, user-friendly Windows desktop application designed for non-technical users and forensic investigators.

### Launching the Desktop GUI

```bash
# Option 1: Via CLI main entrypoint
python -m digitalshield gui

# Option 2: Direct GUI module invocation
python -m digitalshield.gui
```

### Desktop GUI Features
- **Start New Investigation** — Native Windows file dialog with format validation.
- **One-Click Automated Pipeline** — Automatically creates the case, ingests & preserves evidence in the vault, computes SHA-256 baseline, extracts EXIF/technical metadata, generates perceptual fingerprints (aHash, dHash, pHash), runs ELA analysis, and evaluates synthetic media indicators.
- **Thread-Safe Architecture** — Non-blocking background worker threads with responsive live checklists and progress bars.
- **Results Dashboard & Technical Tabs** — Clear anomaly scores, synthetic probability gauges, EXIF details, and HMAC-chained audit log explorer.
- **Instant Report Generation** — Generates and opens Markdown, HTML, and PDF reports directly with one click.
- **Open Existing Case** — Browse registered cases in local storage and inspect previously saved findings.

---

## Full CLI Forensic Workflow

### Step 1 — Create a Forensic Case

```bash
python -m digitalshield case create \
  --name "Social Media Fraud Investigation" \
  --investigator "Officer Alex" \
  --description "Images suspected to be circulated without consent"
```

Output: A `Case ID` like `DS-2026-000001`.

```bash
# List all cases
python -m digitalshield case list

# View a specific case
python -m digitalshield case show DS-2026-000001
```

---

### Step 2 — Import Evidence

```bash
python -m digitalshield evidence import /path/to/image.jpg --case DS-2026-000001
```

- Evidence is **SHA-256 hashed and preserved in a read-only vault**.
- An `Evidence ID` like `EVD-2026-000001` is returned.

```bash
# List evidence for a case
python -m digitalshield evidence list --case DS-2026-000001

# View evidence details
python -m digitalshield evidence show EVD-2026-000001
```

---

### Step 3 — Extract Metadata & EXIF

```bash
python -m digitalshield evidence metadata EVD-2026-000001
```

Extracts: Camera make/model, GPS location, timestamps, resolution, color mode.

---

### Step 4 — Generate Perceptual Fingerprints

```bash
# Fingerprint one piece of evidence
python -m digitalshield evidence fingerprint EVD-2026-000001

# Compare two pieces of evidence for visual similarity
python -m digitalshield evidence compare EVD-2026-000001 EVD-2026-000002
```

---

### Step 5 — Error Level Analysis (ELA)

```bash
python -m digitalshield analyze ela EVD-2026-000001
```

Detects JPEG recompression inconsistencies that may indicate manipulation.

---

### Step 6 — AI Deepfake / Synthetic Media Assessment

```bash
python -m digitalshield analyze deepfake EVD-2026-000001
```

Outputs a synthetic probability score with confidence rating and explicit caveats.

---

### Step 7 — Public URL Provenance Analysis

```bash
# Record a publicly observed source URL
python -m digitalshield provenance add EVD-2026-000001 "https://example.com/post/12345" \
  --account "observed_username"

# List provenance records for a case
python -m digitalshield provenance list --case DS-2026-000001

# View a specific provenance record
python -m digitalshield provenance show PROV-2026-000001

# Get propagation timeline for an evidence item
python -m digitalshield provenance timeline EVD-2026-000001
```

> **Note:** Only public HTTP/HTTPS URLs are accepted. Private IPs, localhost, and authenticated-only pages are blocked by SSRF protection.

---

### Step 8 — Generate Forensic Reports

```bash
# Generate all three formats at once (recommended)
python -m digitalshield report generate DS-2026-000001 --format all

# Or generate individually
python -m digitalshield report generate DS-2026-000001 --format markdown
python -m digitalshield report generate DS-2026-000001 --format html
python -m digitalshield report generate DS-2026-000001 --format pdf

# List all reports for a case
python -m digitalshield report list --case DS-2026-000001

# View report record details
python -m digitalshield report show RPT-2026-000001
```

Reports are saved to:
```
.digitalshield_data/cases/<case_id>/reports/
  report_RPT-2026-000001.md
  report_RPT-2026-000001.html
  report_RPT-2026-000001.pdf
```

---

## What the Forensic Report Contains

Each generated report includes 12 structured sections:

| # | Section |
|:---:|:---|
| 1 | Report Cover & Case Information |
| 2 | Evidence Inventory with SHA-256 Baselines |
| 3 | Technical & EXIF Metadata Findings |
| 4 | Perceptual Hashing & Similarity Results |
| 5 | Error Level Analysis (ELA) |
| 6 | AI Deepfake / Synthetic Media Assessment |
| 7 | Public URL Provenance & Investigative Leads |
| 8 | Origin & Propagation Timeline |
| 9 | Audit Trail & Chain of Custody |
| 10 | Summary of Objective Findings |
| 11 | Forensic & Legal Limitations |
| 12 | Investigator / Case Notes |

---

## Data Storage Structure

All data is stored **fully locally** in `.digitalshield_data/` — no cloud, no external network:

```
.digitalshield_data/
├── cases.json           # Case index
├── evidence.json        # Evidence index
├── reports.json         # Report index
├── audit.log            # Append-only, HMAC-chained audit log
└── cases/
    └── <case_id>/
        ├── evidence/    # Read-only preserved evidence vault
        ├── metadata/    # EXIF records
        ├── fingerprints/# Perceptual hash records
        ├── ela/         # Error Level Analysis results
        ├── deepfake/    # Deepfake assessment records
        ├── provenance/  # Public URL provenance records
        └── reports/     # Generated forensic reports (.md, .html, .pdf)
```

---

## Ethical & Security Guardrails

All operations adhere to the strict rules in [`AGENTS.md`](AGENTS.md):

- **Defensive only** — Designed exclusively for evidence verification and victim support.
- **Evidence immutability** — Original evidence files are never modified; SHA-256 baselines verified on every access.
- **No fabrication** — Reports never invent facts not present in stored data.
- **Neutral attribution language** — Provenance uses terms like *"Reported source"*, *"Observed account"*, *"Publicly observed source"* — never states ownership as fact.
- **Explicit AI limitations** — All ML/AI outputs include probability scores and explicit caveats.
- **No unauthorized access** — No private IP access, no bypassing authentication, no scraping restricted content.
- **Fully offline HTML reports** — Zero external CDNs, fonts, scripts, or trackers.
- **Tamper-evident audit trail** — All actions recorded in an HMAC-chained append-only audit log.

---

## Academic Context

DigitalShield is developed as a **final-year academic project** demonstrating:
- Forensic software engineering practices
- Ethical AI usage in investigative contexts
- Secure local data architecture
- Digital evidence chain-of-custody principles
- Professional forensic documentation standards

---

## License

MIT License — See [`LICENSE`](LICENSE) for details.

