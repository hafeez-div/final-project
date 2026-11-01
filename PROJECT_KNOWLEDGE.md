# PROJECT_KNOWLEDGE.md — DigitalShield Complete Project Reference

> **Generated:** 2026-11-01 | **Status:** Current codebase analysis

---

## 1. Project Overview and Purpose

**DigitalShield** is a Python-based defensive digital forensics and evidence management suite designed as a final-year academic project. It provides a standardised, reproducible workflow for importing, preserving, and analysing digital media (images, documents, screenshots) while maintaining strict forensic integrity (chain of custody, evidence immutability, cryptographic verification).

The tool serves victims of digital crimes (NCII distribution, identity fraud, online harassment) and academic researchers by generating court-ready forensic reports without requiring cloud services or exposing private data externally.

---

## 2. Problem Statement

Digital evidence on social media and messaging platforms is routinely altered, removed, or dismissed as inadmissible due to the lack of forensic-grade collection procedures. Victims need a tool that:
- Preserves evidence with cryptographic proof of integrity.
- Detects potential image manipulation (ELA, deepfake indicators).
- Tracks where stolen media appears publicly.
- Generates professionally formatted forensic reports suitable for legal complaints.

---

## 3. Main Objectives

1. Forensic-grade SHA-256 evidence vaulting (read-only, tamper-evident).
2. Automated EXIF/technical metadata extraction.
3. Perceptual hash fingerprinting (aHash, dHash, pHash) for similarity detection.
4. Error Level Analysis (ELA) manipulation detection.
5. AI-based synthetic/deepfake media probabilistic assessment.
6. Public URL provenance recording with SSRF protection.
7. Automated Google Cloud Vision reverse image search.
8. Investigator-assisted Google Lens reverse image search.
9. Forensic report generation (Markdown, HTML, PDF).
10. Append-only, HMAC-chained audit log (chain of custody).
11. Desktop GUI and CLI interfaces.

---

## 4. Complete Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Language | Python | 3.11+ (tested on 3.13.7) |
| CLI Framework | Click | ≥8.1.0 |
| Terminal Formatting | Rich | ≥13.0.0 |
| Data Validation | Pydantic v2 | ≥2.0.0 |
| Image Processing | Pillow (PIL) | ≥10.0.0 |
| Perceptual Hashing | imagehash | ≥4.3.0 |
| PDF Generation | ReportLab | ≥4.0.0 |
| HTTP Client | urllib (stdlib) + curl-cffi | stdlib + ≥0.5.0 |
| Web Scraping | Scrapling | ≥0.5 |
| Vision AI | google-cloud-vision REST API | ≥3.0.0 (REST, not SDK) |
| GUI | Tkinter (stdlib) | stdlib |
| Testing | pytest + pytest-cov | ≥7.4.0 + ≥4.1.0 |
| Storage | JSON files (flat-file store) | — |
| Build System | setuptools / pyproject.toml | — |

### Notable: Currently Missing Dependencies
The following packages are declared in `pyproject.toml` but **not installed** in the current environment:
- `imagehash` — required by fingerprinting, provenance, web_discovery
- `rich` — required by CLI

---

## 5. Full Directory Structure

```
final-project/
├── digitalshield/                    # Main Python package
│   ├── __init__.py                   # Version: 0.1.0
│   ├── __main__.py                   # `python -m digitalshield` entry point → cli.main.main()
│   ├── case_manager/
│   │   ├── manager.py                # CaseManager class
│   │   ├── models.py                 # Case (Pydantic BaseModel)
│   │   └── __init__.py
│   ├── cli/
│   │   ├── main.py                   # Full CLI definition (Click groups: case, evidence, analyze, provenance, report, gui)
│   │   └── __init__.py
│   ├── detection/
│   │   ├── ela.py                    # ELADetector class
│   │   ├── deepfake.py               # BaselineDeepfakeDetector + DeepfakeAssessmentService
│   │   ├── interfaces.py             # BaseDeepfakeDetector ABC
│   │   ├── models.py                 # ELAResult, ELAStatistics, DeepfakeAnalysisResult, DetectorType
│   │   └── __init__.py
│   ├── evidence/
│   │   ├── manager.py                # EvidenceManager class (import, vault, SHA-256)
│   │   ├── models.py                 # Evidence (Pydantic BaseModel)
│   │   └── __init__.py
│   ├── fingerprinting/
│   │   ├── service.py                # FingerprintService (aHash, dHash, pHash, comparison)
│   │   ├── models.py                 # FingerprintResult, ComparisonResult, AlgorithmFingerprint, ComparisonMetric
│   │   └── __init__.py
│   ├── gui/
│   │   ├── app.py                    # DigitalShieldApp (tk.Tk), launch_gui()
│   │   ├── theme.py                  # Colors, Fonts, apply_theme()
│   │   ├── workers.py                # AnalysisWorker, ReportWorker, WebDiscoveryWorker (threading.Thread)
│   │   ├── __init__.py               # TCL/TK env setup for Windows + exports
│   │   ├── __main__.py               # Direct GUI launch
│   │   └── screens/
│   │       ├── home.py               # HomeScreen (Start/Open Investigation)
│   │       ├── new_case.py           # NewCaseScreen (form + file picker)
│   │       ├── progress.py           # ProgressScreen (live checklist + progress bar)
│   │       ├── results.py            # ResultsScreen (full results dashboard)
│   │       ├── details.py            # DetailsScreen (tabbed EXIF/fingerprint/ELA/deepfake tabs)
│   │       ├── provenance.py         # ProvenanceScreen (provenance + Google Lens management)
│   │       ├── reports.py            # ReportsScreen (report generation + open files)
│   │       ├── open_case.py          # OpenCaseScreen (browse existing cases)
│   │       └── __init__.py
│   ├── metadata/
│   │   ├── extractor.py              # MetadataExtractor class
│   │   ├── models.py                 # MetadataResult (Pydantic BaseModel)
│   │   └── __init__.py
│   ├── monitoring/
│   │   └── __init__.py               # Empty stub — monitoring NOT implemented
│   ├── provenance/
│   │   ├── service.py                # ProvenanceService class
│   │   ├── client.py                 # SafePublicClient (SSRF-safe HTTP fetcher)
│   │   ├── models.py                 # ProvenanceRecord (Pydantic BaseModel)
│   │   └── __init__.py
│   ├── reporting/
│   │   ├── service.py                # ReportingService class
│   │   ├── models.py                 # ReportData, ReportMetadata, ReportRecord, CaseInfo, EvidenceItemReport
│   │   └── renderers/
│   │       ├── html_renderer.py      # HTMLRenderer.render() — 100% offline standalone HTML
│   │       ├── markdown_renderer.py  # MarkdownRenderer.render() — GFM Markdown
│   │       ├── pdf_renderer.py       # PDFRenderer.render() — ReportLab paginated PDF
│   │       └── __init__.py
│   ├── security/
│   │   ├── audit.py                  # AuditLogger class (HMAC-chained append-only log)
│   │   └── __init__.py
│   ├── storage/
│   │   ├── json_store.py             # JSONStore class (flat JSON files persistence)
│   │   └── __init__.py
│   └── web_discovery/
│       ├── service.py                # WebDiscoveryService (automated Google Cloud Vision)
│       ├── lens_service.py           # GoogleLensService (manual investigator-assisted)
│       ├── vision_provider.py        # VisionWebDetectionProvider (REST API client)
│       ├── lens_models.py            # GoogleLensSession, GoogleLensResult, detect_platform_name
│       ├── models.py                 # WebDiscoverySession, WebDiscoveryResult (Pydantic)
│       ├── page_enricher.py          # enrich_page(), normalize_url(), deduplicate_urls() (Scrapling)
│       ├── __init__.py
│       └── providers/
│           ├── base_provider.py      # BaseReverseImageProvider ABC
│           └── __init__.py
├── tests/
│   ├── test_audit.py                 # 1 test: audit chain verification
│   ├── test_auto_reverse_search.py   # Web discovery tests (needs imagehash)
│   ├── test_case_manager.py          # 3 tests: case CRUD
│   ├── test_cli.py                   # CLI integration tests (needs rich)
│   ├── test_deepfake.py              # Deepfake assessment tests (needs imagehash)
│   ├── test_detection.py             # 9 tests: ELA analysis
│   ├── test_evidence_manager.py      # 9 tests: evidence import/vault
│   ├── test_fingerprinting.py        # Perceptual hash tests (needs imagehash)
│   ├── test_google_lens.py           # Google Lens service tests (needs imagehash)
│   ├── test_gui.py                   # GUI tests (needs imagehash)
│   ├── test_new_case_source_url.py   # New case URL validation tests (needs imagehash)
│   ├── test_provenance.py            # Provenance service tests (needs imagehash)
│   ├── test_reporting.py             # Report generation tests (needs imagehash)
│   ├── test_web_discovery.py         # Full web discovery integration tests (needs imagehash)
│   └── __init__.py
├── docs/
│   ├── ARCHITECTURE.md               # High-level architecture overview
│   ├── PROVENANCE.md                 # Provenance subsystem documentation
│   └── REPORTING.md                  # Reporting subsystem documentation
├── .env.example                      # Template: CLAUDE_API, ELEVEN_LABS_API keys
├── .gitignore
├── AGENTS.md                         # Strict ethical + development guidelines
├── CONTRIBUTING.md
├── LICENSE                           # MIT
├── PROJECT_SPEC.md                   # Functional requirements specification
├── pyproject.toml                    # Build configuration + dependencies
├── README.md                         # Full user documentation
└── SECURITY.md                       # Security policies
```

---

## 6. Module-by-Module Explanations

### 6.1 `digitalshield.cli.main` — CLI Entry Point
**File:** [`digitalshield/cli/main.py`](digitalshield/cli/main.py)

The top-level Click CLI group `cli` with sub-groups:
- `case` → `create`, `list`, `show` commands
- `evidence` → `import`, `list`, `show`, `fingerprint`, `compare`
- `analyze` → `ela`, `deepfake`
- `provenance` → `add`, `list`, `show`, `timeline`
- `report` → `generate`, `list`, `show`
- `gui` → launches `digitalshield.gui.app.launch_gui()`

The `main()` function is the `[project.scripts]` entry point: `digitalshield = digitalshield.cli.main:main`.

### 6.2 `digitalshield.case_manager` — Case Lifecycle
**Files:** [`case_manager/manager.py`](digitalshield/case_manager/manager.py), [`case_manager/models.py`](digitalshield/case_manager/models.py)

**`Case` model fields:** `case_id`, `name`, `investigator`, `description`, `source_url`, `created_at`, `status`, `vault_path`, `evidence_count`

**`CaseManager` methods:**
- `create_case()` — generates `DS-YYYY-XXXXXX` ID, creates vault dirs, persists, audits
- `get_case()`, `list_cases()`, `increment_evidence_count()`
- Base dir resolution: env var `DIGITALSHIELD_DATA_DIR` → `.digitalshield_data/`

### 6.3 `digitalshield.evidence` — Evidence Ingestion & Vaulting
**Files:** [`evidence/manager.py`](digitalshield/evidence/manager.py), [`evidence/models.py`](digitalshield/evidence/models.py)

**`EvidenceManager` workflow (12 steps):**
1. File existence check
2. Extension validation against `SUPPORTED_EXTENSIONS` dict
3. Case ID existence check
4. Chunked SHA-256 (64 KB chunks) — `calculate_sha256()`
5. MIME inference from magic bytes — `infer_mime_type()`
6. Duplicate check within case by SHA-256
7. Generate `EVD-YYYY-XXXXXX` ID
8. `shutil.copy2()` to vault (NEVER modifies original)
9. Lock copied file read-only: `os.chmod(0o444)`
10. Create `Evidence` model
11. Persist to JSONStore + update case evidence count
12. Update `evidence_manifest.json` in vault + audit log

**Supported extensions:** `.jpg`, `.jpeg`, `.png`, `.webp`, `.gif`, `.mp4`, `.mov`, `.avi`, `.txt`, `.pdf`

### 6.4 `digitalshield.metadata` — EXIF Metadata Extraction
**Files:** [`metadata/extractor.py`](digitalshield/metadata/extractor.py), [`metadata/models.py`](digitalshield/metadata/models.py)

**`MetadataExtractor.extract()`** reads the preserved vault copy (read-only `rb` mode) via Pillow, extracts:
- Technical: `file_format`, `width_px`, `height_px`, `color_mode`, `file_size_bytes`, `mime_type`
- EXIF tags: `Make`, `Model`, `Software`, `DateTime`, `DateTimeOriginal`, `ExposureTime`, `FNumber`, `ISOSpeedRatings`, `FocalLength`, `Flash`
- GPS: `gps_latitude`, `gps_longitude`, `gps_altitude` (DMS → decimal conversion)
- Never fabricates missing fields (always `None`)

### 6.5 `digitalshield.fingerprinting` — Perceptual Hashing
**Files:** [`fingerprinting/service.py`](digitalshield/fingerprinting/service.py), [`fingerprinting/models.py`](digitalshield/fingerprinting/models.py)

**`FingerprintService` methods:**
- `generate_fingerprints(evidence_id)` — aHash, dHash, pHash (all 64-bit hex strings)
- `compare_fingerprints(ev_a, ev_b)` — Hamming distance + normalized similarity (0.0–1.0)
- `calculate_hamming_distance()`, `calculate_normalized_similarity()` — static helpers
- Results cached in JSONStore; `force_recompute=True` bypasses cache

**Requires: `imagehash` package (not installed)**

### 6.6 `digitalshield.detection.ela` — Error Level Analysis
**File:** [`detection/ela.py`](digitalshield/detection/ela.py)

**`ELADetector.analyze_evidence()`:**
1. Opens vault image in read-only mode with Pillow
2. Converts to RGB, saves to in-memory BytesIO at target JPEG quality
3. Computes pixel-wise absolute difference (`ImageChops.difference`)
4. Extracts: `mean_error`, `max_error`, `stddev_error`, `rms_error`, `high_error_pixels`, `high_error_ratio`, `high_error_bounding_box`
5. Normalised anomaly score: `0.4*norm_stddev + 0.3*norm_mean + 0.3*norm_ratio` → [0.0, 1.0]
6. Confidence: 85% (≥200px), 80% (≥100px), 70% (smaller)
7. Assessment: Low (<0.25) / Moderate (<0.60) / High (≥0.60)

**Result dual-persisted:** central `ela.json` + `cases/<case_id>/analysis/ela_<ev_id>.json`

### 6.7 `digitalshield.detection.deepfake` — Synthetic Media Assessment
**Files:** [`detection/deepfake.py`](digitalshield/detection/deepfake.py), [`detection/interfaces.py`](digitalshield/detection/interfaces.py), [`detection/models.py`](digitalshield/detection/models.py)

**Architecture:** `BaseDeepfakeDetector` ABC → `BaselineDeepfakeDetector` (injected into `DeepfakeAssessmentService`)

**`BaselineDeepfakeDetector.analyze()`** heuristic scoring:
- Baseline prior: 0.20
- EXIF absent: +0.15; EXIF present: −0.10
- Common generative resolution (e.g., 512×512, 1024×1024): +0.20; square aspect: +0.05
- Low RGB channel variance (<20.0 stddev): +0.10
- High compression variance (diff_stddev >15.0): +0.15
- Final score clamped to [0.05, 0.95]
- `DetectorType.HEURISTIC_BASELINE` — clearly labelled, not a trained ML model

**Result dual-persisted:** `deepfake.json` + `cases/<case_id>/analysis/deepfake_<ev_id>.json`

### 6.8 `digitalshield.provenance` — Public URL Provenance
**Files:** [`provenance/service.py`](digitalshield/provenance/service.py), [`provenance/client.py`](digitalshield/provenance/client.py), [`provenance/models.py`](digitalshield/provenance/models.py)

**`SafePublicClient.validate_url()`** SSRF protection:
- Scheme whitelist: `http://`, `https://` only
- String blocklist: `localhost`, `127.0.0.1`, `::1`, `0.0.0.0`
- DNS resolution + IP range checks: `is_private`, `is_loopback`, `is_link_local`, `is_reserved`, `is_multicast`
- Redirect validation (up to 3 hops), 10s timeout, 5 MB response cap

**`ProvenanceService.record_provenance()`:**
1. Validates source URL via SafePublicClient
2. Optionally fetches page (HTTP) to extract title (`<title>` tag)
3. Optionally fetches media URL and compares perceptual hashes against evidence
4. Generates `PRV-YYYY-XXXXXX` ID
5. Dual-persists record + audits `PROVENANCE_SOURCE_RECORDED` and `PROVENANCE_MEDIA_MATCHED`

**`get_provenance_timeline()`** builds chronological timeline combining vault import event + all public source discovery events.

### 6.9 `digitalshield.web_discovery` — Automated Reverse Image Search

Two distinct sub-systems:

#### A. `WebDiscoveryService` (Automated — Google Cloud Vision)
**File:** [`web_discovery/service.py`](digitalshield/web_discovery/service.py)

Requires `GOOGLE_CLOUD_API_KEY` environment variable. Flow:
1. Call `VisionWebDetectionProvider.search_web()` → REST POST to Vision API
2. Collect candidates (exact, partial, visually similar, pages with images)
3. Deduplicate URLs via `normalize_url()`
4. For each candidate: scrape page via Scrapling (`enrich_page()`), attempt media download, compute perceptual hash similarity
5. Generate `WDS-YYYY-XXXXXX` session IDs and `WDR-YYYY-XXXXXX` result IDs
6. Dual-persist session + results; audit each step

#### B. `GoogleLensService` (Manual/Assisted)
**File:** [`web_discovery/lens_service.py`](digitalshield/web_discovery/lens_service.py)

- `initiate_lens_search()` → opens `https://lens.google.com/` in browser, creates `GLS-YYYY-XXXXXX` session
- `record_match_result()` → investigator manually enters URLs found in Lens
- `mark_session_no_results()` → logs negative result
- All results stored in same web_discovery_sessions/results JSONStore collections

### 6.10 `digitalshield.reporting` — Forensic Report Generation
**Files:** [`reporting/service.py`](digitalshield/reporting/service.py), [`reporting/models.py`](digitalshield/reporting/models.py), renderers

**`ReportingService.generate_report()`:**
1. `compile_report_data()` — aggregates case, evidence, metadata, fingerprints, ELA, deepfake, provenance, web discovery, audit events
2. Renders via `MarkdownRenderer.render()`, `HTMLRenderer.render()`, `PDFRenderer.render()`
3. Saves to `.digitalshield_data/cases/<case_id>/reports/report_<RPT_ID>.[md|html|pdf]`
4. Persists `ReportRecord` to JSONStore + audits `REPORT_GENERATED`

**12 report sections:** Cover, Evidence Inventory, Technical/EXIF Metadata, Perceptual Hashing, ELA, Deepfake, Public URL Provenance, Origin Timeline, Audit Trail/Chain of Custody, Summary Findings, Forensic Limitations, Investigator Notes.

**HTML renderer:** 100% offline — no CDNs, external fonts, or trackers.

### 6.11 `digitalshield.storage.json_store` — Data Persistence
**File:** [`storage/json_store.py`](digitalshield/storage/json_store.py)

Flat JSON files under `.digitalshield_data/`:
- `cases.json` — `{case_id: {case dict}}`
- `evidence.json` — `{evidence_id: {evidence dict}}`
- `metadata.json` — `{evidence_id: {metadata dict}}`
- `fingerprints.json` — `{evidence_id: {fingerprint dict}}`
- `ela.json` — `{evidence_id: {ELA dict}}`
- `deepfake.json` — `{evidence_id: {deepfake dict}}`
- `provenance.json` — `{provenance_id: {provenance dict}}`
- `reports.json` — `{report_id: {report dict}}`
- `web_discovery_sessions.json` — `{session_id: {session dict}}`
- `web_discovery_results.json` — `{result_id: {result dict}}`

No locking — single-user desktop application assumption. Race conditions possible under concurrent access.

### 6.12 `digitalshield.security.audit` — Audit Logging
**File:** [`security/audit.py`](digitalshield/security/audit.py)

**`AuditLogger`** — HMAC-chained append-only log:
- Each entry: `{timestamp, action, actor, details, previous_hash, entry_hash}`
- `previous_hash` = SHA-256 of previous entry's JSON (genesis = "0"×64)
- `entry_hash` = SHA-256 of current entry JSON (sort_keys=True)
- Written to `audit.log` — one JSON object per line (JSONL)

**Actions logged:** `CASE_CREATED`, `EVIDENCE_IMPORTED`, `SHA256_GENERATED`, `METADATA_EXTRACTED`, `FINGERPRINTS_GENERATED`, `FINGERPRINTS_COMPARED`, `ELA_ANALYSIS_EXECUTED`, `DEEPFAKE_ASSESSMENT_EXECUTED`, `PROVENANCE_SOURCE_RECORDED`, `PROVENANCE_MEDIA_MATCHED`, `REPORT_GENERATED`, `AUTOMATIC_REVERSE_SEARCH_STARTED`, `REVERSE_SEARCH_PROVIDER_REQUESTED`, `PUBLIC_SOURCE_SCRAPED`, `CANDIDATE_IMAGE_VERIFIED`, `CANDIDATE_IMAGE_UNVERIFIED`, `PUBLIC_SOURCE_DISCOVERED`, `REVERSE_SEARCH_COMPLETED`, `REVERSE_SEARCH_FAILED`, `GOOGLE_LENS_SEARCH_INITIATED`, `GOOGLE_LENS_RESULT_RECORDED`, `GOOGLE_LENS_NO_RESULTS_RECORDED`

### 6.13 `digitalshield.gui` — Desktop GUI
**Files:** [`gui/app.py`](digitalshield/gui/app.py), [`gui/workers.py`](digitalshield/gui/workers.py), [`gui/screens/`](digitalshield/gui/screens/)

Framework: **Tkinter** (stdlib). Custom dark theme via `theme.py`.

**8 screens registered in `DigitalShieldApp`:**
1. `HomeScreen` — Start New Investigation / Open Existing Case buttons
2. `NewCaseScreen` — Case form (name, investigator, description, file picker, source URL)
3. `ProgressScreen` — Live 7-step checklist + progress bar (polling via `after(100)`)
4. `ResultsScreen` — Full results dashboard with scores, buttons
5. `DetailsScreen` — Tabbed detail view (EXIF, Fingerprints, ELA, Deepfake)
6. `ProvenanceScreen` — Provenance records + Google Lens management
7. `ReportsScreen` — Report generation + open generated files
8. `OpenCaseScreen` — Browse and load existing cases

**Workers (daemon threads):**
- `AnalysisWorker` — full 7-step pipeline (case → evidence → metadata → fingerprints → ELA → deepfake → web discovery)
- `ReportWorker` — report generation
- `WebDiscoveryWorker` — re-run web discovery on demand
- Communication: `queue.Queue` + `app.after(100)` polling

### 6.14 `digitalshield.monitoring` — Monitoring Stub
**File:** [`monitoring/__init__.py`](digitalshield/monitoring/__init__.py) — **empty stub, NOT implemented**

---

## 7. System Architecture

```
User
  │
  ├─── CLI (Click)          digitalshield/cli/main.py
  │        │
  └─── GUI (Tkinter)        digitalshield/gui/app.py
           │ (AnalysisWorker thread)
           │
           ▼
    ┌─────────────────────────────────────────┐
    │           Service Layer                  │
    │  CaseManager  EvidenceManager            │
    │  MetadataExtractor  FingerprintService   │
    │  ELADetector  DeepfakeAssessmentService  │
    │  ProvenanceService  WebDiscoveryService  │
    │  GoogleLensService  ReportingService     │
    └─────────────────────────────────────────┘
           │                    │
           ▼                    ▼
    JSONStore              AuditLogger
    (flat JSON files)      (HMAC-chained JSONL)
           │
           ▼
    .digitalshield_data/
    ├── cases.json, evidence.json, etc.
    └── cases/<case_id>/
        ├── evidence/        (read-only vault)
        ├── analysis/        (derived JSON results)
        └── reports/         (.md, .html, .pdf)
```

---

## 8. Application Execution Flow

### CLI Flow
```
python -m digitalshield <command>
  └→ digitalshield/__main__.py
       └→ cli.main.main()
            └→ Click routes to command handler
                 └→ Instantiates service class(es)
                      └→ Calls service method
                           └→ Reads/writes JSONStore + AuditLogger
                                └→ Returns model → Rich console output
```

### GUI Flow
```
python -m digitalshield gui
  └→ launch_gui() → DigitalShieldApp(tk.Tk)
       └→ Registers 8 screens, shows HomeScreen
            └→ User fills NewCaseScreen → "Start Forensic Analysis"
                 └→ app.start_investigation()
                      └→ ProgressScreen shown
                      └→ AnalysisWorker(thread).start()
                           │  (background thread)
                           ├─ Step 0: CaseManager.create_case()
                           ├─ Step 1: EvidenceManager.import_evidence()
                           ├─ Step 2: MetadataExtractor.extract()
                           ├─ Step 3: FingerprintService.generate_fingerprints()
                           ├─ Step 4: ELADetector.analyze_evidence()
                           ├─ Step 5: DeepfakeAssessmentService.assess_evidence()
                           └─ Step 6: WebDiscoveryService.run_search()
                      └→ msg_queue.put({type: "complete", data: payload})
                           └→ app._poll_analysis_queue() (after 100ms)
                                └→ case_data stored → show ResultsScreen
```

---

## 9. Complete Feature List

| # | Feature | Status |
|---|---|---|
| 1 | Case Management (create, list, show) | ✅ Complete |
| 2 | Evidence Ingestion & SHA-256 Vaulting | ✅ Complete |
| 3 | MIME type detection from magic bytes | ✅ Complete |
| 4 | Duplicate evidence detection (SHA-256) | ✅ Complete |
| 5 | Evidence manifest (evidence_manifest.json) | ✅ Complete |
| 6 | EXIF/Technical Metadata Extraction | ✅ Complete |
| 7 | GPS Coordinate Extraction | ✅ Complete |
| 8 | Perceptual Hashing (aHash, dHash, pHash) | ✅ Complete |
| 9 | Fingerprint Comparison (Hamming distance) | ✅ Complete |
| 10 | Error Level Analysis (ELA) | ✅ Complete |
| 11 | AI Deepfake Assessment (heuristic baseline) | ✅ Complete |
| 12 | SSRF-Protected Public URL Provenance Recording | ✅ Complete |
| 13 | Public Media Similarity Matching | ✅ Complete |
| 14 | Provenance Timeline Generation | ✅ Complete |
| 15 | Automated Google Cloud Vision Web Detection | ✅ Complete |
| 16 | Scrapling-powered candidate page enrichment | ✅ Complete |
| 17 | Investigator-Assisted Google Lens Search | ✅ Complete |
| 18 | Markdown Report Generation | ✅ Complete |
| 19 | HTML Report Generation (100% offline) | ✅ Complete |
| 20 | PDF Report Generation (ReportLab) | ✅ Complete |
| 21 | HMAC-chained Audit Log | ✅ Complete |
| 22 | Desktop GUI (Tkinter, 8 screens) | ✅ Complete |
| 23 | Thread-safe background analysis pipeline | ✅ Complete |
| 24 | Source URL recording at intake | ✅ Complete |
| 25 | Open Existing Case (GUI) | ✅ Complete |
| 26 | Monitoring / reupload framework | ❌ NOT IMPLEMENTED (empty stub) |
| 27 | Screenshot OCR Analysis | ❌ NOT IMPLEMENTED |
| 28 | Video frame analysis for web discovery | ❌ NOT IMPLEMENTED (noted in code) |
| 29 | Trained ML deepfake detector | ❌ NOT IMPLEMENTED (heuristic baseline only) |
| 30 | SQLite database option | ❌ NOT IMPLEMENTED (JSON-only) |

---

## 10. Data Flow Between Components

```
Evidence File
    │
    ├──[EvidenceManager]──────────────────────────────────────────────┐
    │   - SHA-256 hash computed                                        │
    │   - File copied to vault (read-only)                             │
    │   - Evidence record → JSONStore(evidence.json)                   │
    │   - Case evidence_count incremented                              │
    │   - Audit: EVIDENCE_IMPORTED + SHA256_GENERATED                 │
    │                                                                  │
    ├──[MetadataExtractor]────────────────────────────────────────────┤
    │   reads vault path → Pillow → EXIF dict                         │
    │   → JSONStore(metadata.json) + audit: METADATA_EXTRACTED        │
    │                                                                  │
    ├──[FingerprintService]───────────────────────────────────────────┤
    │   reads vault path → imagehash → aHash/dHash/pHash strings      │
    │   → JSONStore(fingerprints.json) + audit: FINGERPRINTS_GENERATED│
    │                                                                  │
    ├──[ELADetector]──────────────────────────────────────────────────┤
    │   reads vault path → in-memory JPEG recompression diff          │
    │   → ELAResult + JSONStore(ela.json)                             │
    │   + cases/<id>/analysis/ela_<evid>.json                         │
    │   + audit: ELA_ANALYSIS_EXECUTED                                 │
    │                                                                  │
    ├──[DeepfakeAssessmentService]────────────────────────────────────┤
    │   reads vault path → heuristic scoring                           │
    │   → DeepfakeAnalysisResult + JSONStore(deepfake.json)           │
    │   + cases/<id>/analysis/deepfake_<evid>.json                    │
    │   + audit: DEEPFAKE_ASSESSMENT_EXECUTED                          │
    │                                                                  │
    ├──[ProvenanceService]────────────────────────────────────────────┤
    │   fetch public URL (SSRF-safe) → compare media hash vs evidence  │
    │   → ProvenanceRecord + JSONStore(provenance.json)               │
    │   + cases/<id>/analysis/provenance_<prvid>.json                 │
    │   + audit: PROVENANCE_SOURCE_RECORDED + PROVENANCE_MEDIA_MATCHED│
    │                                                                  │
    ├──[WebDiscoveryService]──────────────────────────────────────────┤
    │   reads vault → Vision API → candidate URLs                      │
    │   → scrape each → compare hash → WebDiscoverySession+Results    │
    │   → JSONStore(web_discovery_sessions/results.json)              │
    │   + cases/<id>/analysis/web_discovery/                           │
    │   + audit: multiple events                                        │
    │                                                                  │
    └──[ReportingService]─────────────────────────────────────────────┘
        reads ALL JSONStore data for case_id
        → ReportData (unified model)
        → MarkdownRenderer/HTMLRenderer/PDFRenderer
        → cases/<id>/reports/report_<rptid>.[md|html|pdf]
        → JSONStore(reports.json)
        + audit: REPORT_GENERATED
```

---

## 11. Storage Architecture

### Physical Layout
```
.digitalshield_data/             (default; overridden by DIGITALSHIELD_DATA_DIR env)
├── audit.log                    HMAC-chained JSONL (never deleted)
├── cases.json                   {case_id → case_dict}
├── evidence.json                {evidence_id → evidence_dict}
├── metadata.json                {evidence_id → metadata_dict}
├── fingerprints.json            {evidence_id → fingerprint_dict}
├── ela.json                     {evidence_id → ela_dict}
├── deepfake.json                {evidence_id → deepfake_dict}
├── provenance.json              {provenance_id → provenance_dict}
├── reports.json                 {report_id → report_dict}
├── web_discovery_sessions.json  {session_id → session_dict}
├── web_discovery_results.json   {result_id → result_dict}
└── cases/
    └── <case_id>/
        ├── evidence/
        │   ├── evidence_manifest.json    (read-only: 0o444)
        │   └── EVD-YYYY-XXXXXX_<filename>  (read-only: 0o444)
        ├── analysis/
        │   ├── ela_EVD-YYYY-XXXXXX.json
        │   ├── deepfake_EVD-YYYY-XXXXXX.json
        │   ├── provenance_PRV-YYYY-XXXXXX.json
        │   ├── web_discovery/
        │   │   ├── session_WDS-YYYY-XXXXXX.json
        │   │   └── result_WDR-YYYY-XXXXXX.json
        │   └── google_lens/
        │       ├── session_GLS-YYYY-XXXXXX.json
        │       └── result_GLR-YYYY-XXXXXX.json
        └── reports/
            ├── report_RPT-YYYY-XXXXXX.md
            ├── report_RPT-YYYY-XXXXXX.html
            └── report_RPT-YYYY-XXXXXX.pdf
```

### ID Scheme
| Entity | Format | Example |
|---|---|---|
| Case | `DS-YYYY-XXXXXX` | `DS-2026-000001` |
| Evidence | `EVD-YYYY-XXXXXX` | `EVD-2026-000001` |
| Provenance | `PRV-YYYY-XXXXXX` | `PRV-2026-000001` |
| Report | `RPT-YYYY-XXXXXX` | `RPT-2026-000001` |
| Vision Session | `WDS-YYYY-XXXXXX` | `WDS-2026-000001` |
| Vision Result | `WDR-YYYY-XXXXXX` | `WDR-2026-000001` |
| Lens Session | `GLS-YYYY-XXXXXX` | `GLS-2026-000001` |
| Lens Result | `GLR-YYYY-XXXXXX` | `GLR-2026-000001` |

---

## 12. Security Architecture

| Control | Implementation |
|---|---|
| Evidence immutability | `shutil.copy2()` to vault + `os.chmod(0o444)` |
| SHA-256 integrity | Chunked 64 KB reads; digest stored in `evidence.json` |
| Duplicate rejection | SHA-256 match check before import |
| Audit chain integrity | HMAC: each entry SHA-256 hashes previous entry |
| SSRF protection | URL scheme whitelist, DNS resolution, IP range checks, redirect validation |
| Response limits | 10s timeout, 5 MB max response body |
| API key handling | Environment variables only; never hard-coded or logged |
| .env loading | Only if `GOOGLE_CLOUD_API_KEY` not in `os.environ` and not in test mode |
| Probabilistic language | All AI/ELA outputs include explicit caveats; `DetectorType` enum enforced |
| Neutral attribution | No language claiming guilt/ownership in any output |
| Offline reports | HTML uses no CDNs, external fonts, or scripts |

### Known Security Weaknesses
1. **No file locking** in `JSONStore` — concurrent writes could corrupt JSON files.
2. **`os.chmod(0o444)`** on Windows sets permissions but Windows does not enforce POSIX-style read-only fully — files can still be deleted/overwritten by owner.
3. **No authentication** — all local data is accessible to any local user.
4. **Hardcoded student paths** in `vision_provider.py` (line 83-84): `C:/Users/student/...` — academic artefact.
5. **`.env.example` contains obviously fake keys** which is correct practice, but actual `.env` is in `.gitignore`.

---

## 13. GUI Workflow

### Navigation Graph
```
HomeScreen
  ├── "Start New Investigation" → NewCaseScreen
  │       └── "Start Forensic Analysis" → ProgressScreen → ResultsScreen
  │               ├── "View Detailed Findings" → DetailsScreen
  │               ├── "Provenance & Web Sources" → ProvenanceScreen
  │               ├── "Generate Reports" → ReportsScreen
  │               └── "← Back" (to home)
  └── "Open Existing Case" → OpenCaseScreen
          └── Select case → ResultsScreen (load_data)
```

### Screen Details

**HomeScreen** (`screens/home.py`): Two primary buttons. No data required.

**NewCaseScreen** (`screens/new_case.py`):
- Fields: Investigator Name, Case Name, Description, Evidence File, Public Source URL
- File picker: `tkinter.filedialog.askopenfilename()` filtered by supported formats
- URL validation: `SafePublicClient.validate_url()` — SSRF-checked before submission
- Submit → `app.start_investigation()`

**ProgressScreen** (`screens/progress.py`):
- 7-step checklist with running/complete/pending indicators
- Progress bar (`ttk.Progressbar`)
- Polls `msg_queue` via `app.after(100, _poll_analysis_queue)`

**ResultsScreen** (`screens/results.py`):
- Displays case info, SHA-256 digest, MIME type
- ELA anomaly score gauge, deepfake probability score
- Buttons: View Details, Provenance, Reports, Back

**DetailsScreen** (`screens/details.py`):
- Tabbed notebook: EXIF Metadata | Perceptual Fingerprints | ELA Statistics | Deepfake Assessment

**ProvenanceScreen** (`screens/provenance.py`):
- Table of provenance records
- Google Lens session management (initiate, record result, mark no results)
- Automated web discovery re-run button (requires GOOGLE_CLOUD_API_KEY)

**ReportsScreen** (`screens/reports.py`):
- Checkboxes: Markdown, HTML, PDF
- "Generate Reports" → `ReportWorker` thread
- File open buttons post-generation

**OpenCaseScreen** (`screens/open_case.py`):
- Scrollable list of all registered cases
- Select → loads case data → navigates to ResultsScreen

---

## 14. CLI Commands and Usage

```bash
# Case management
python -m digitalshield case create --name "Name" --investigator "Name" --description "Desc"
python -m digitalshield case list
python -m digitalshield case show DS-2026-000001

# Evidence management
python -m digitalshield evidence import /path/file.jpg --case DS-2026-000001
python -m digitalshield evidence list --case DS-2026-000001
python -m digitalshield evidence show EVD-2026-000001
python -m digitalshield evidence fingerprint EVD-2026-000001
python -m digitalshield evidence compare EVD-2026-000001 EVD-2026-000002

# NOTE: `evidence metadata` command is missing from CLI despite MetadataExtractor existing

# Analysis
python -m digitalshield analyze ela EVD-2026-000001 [--quality 90]
python -m digitalshield analyze deepfake EVD-2026-000001

# Provenance
python -m digitalshield provenance add EVD-2026-000001 "https://example.com" [--account user] [--media-url url] [--source-timestamp ts] [--notes text]
python -m digitalshield provenance list --case DS-2026-000001
python -m digitalshield provenance show PRV-2026-000001
python -m digitalshield provenance timeline EVD-2026-000001

# Reports
python -m digitalshield report generate DS-2026-000001 [--format all|markdown|html|pdf]
python -m digitalshield report list --case DS-2026-000001
python -m digitalshield report show RPT-2026-000001

# GUI
python -m digitalshield gui
```

### Missing CLI Commands (service exists, no CLI binding)
- `evidence metadata <ev_id>` — MetadataExtractor is fully implemented but has no CLI command
- `discover web <ev_id>` — WebDiscoveryService has no CLI command
- `discover lens <ev_id>` — GoogleLensService has no CLI command

---

## 15. External APIs and Integrations

| Integration | Purpose | Key Source | Status |
|---|---|---|---|
| Google Cloud Vision Web Detection | Reverse image search | `GOOGLE_CLOUD_API_KEY` env var | ✅ Implemented, requires billing |
| Google Lens portal | Manual investigator search | N/A (browser-based) | ✅ Implemented (opens browser) |
| Public web pages (HTTP/HTTPS) | Provenance URL fetching | None | ✅ SSRF-protected |
| Scrapling | HTML content extraction from candidate pages | None | ✅ Implemented |

### Not Implemented
- Claude API (key in `.env.example` — not used)
- ElevenLabs API (key in `.env.example` — not used)
- Any trained ML deepfake model API

---

## 16. Report-Generation Workflow

```
report generate DS-2026-000001 --format all
    │
    └→ ReportingService.generate_report(case_id, formats=["markdown","html","pdf"])
         │
         ├→ _generate_report_id() → RPT-2026-000001
         │
         ├→ compile_report_data(case_id)
         │   ├─ CaseManager.get_case()
         │   ├─ EvidenceManager.list_evidence()
         │   ├─ JSONStore.get_metadata() per evidence
         │   ├─ JSONStore.get_fingerprints() per evidence
         │   ├─ JSONStore.get_ela() per evidence
         │   ├─ JSONStore.get_deepfake() per evidence
         │   ├─ ProvenanceService.get_provenance_timeline() per evidence
         │   ├─ JSONStore.list_provenance_by_case()
         │   ├─ AuditLogger.get_events_by_case()
         │   ├─ JSONStore.list_web_discovery_sessions_by_case()
         │   └─ JSONStore.list_web_discovery_results_by_case()
         │   → ReportData (unified model)
         │
         ├→ MarkdownRenderer.render(report_data) → .md file
         ├→ HTMLRenderer.render(report_data) → .html file
         └→ PDFRenderer.render(report_data, path) → .pdf file
              (ReportLab: paginated, page numbers, headers, footers)
```

---

## 17. Test Coverage and Current Test Status

### Test Files
| File | Tests | Status |
|---|---|---|
| `test_audit.py` | 1 | ✅ Passes |
| `test_case_manager.py` | 3 | ✅ Passes |
| `test_detection.py` | 9 | ✅ Passes |
| `test_evidence_manager.py` | 9 | ✅ Passes |
| `test_auto_reverse_search.py` | ~10 | ❌ Import error (missing `imagehash`) |
| `test_cli.py` | ~15 | ❌ Import error (missing `rich`) |
| `test_deepfake.py` | ~8 | ❌ Import error (missing `imagehash`) |
| `test_fingerprinting.py` | ~10 | ❌ Import error (missing `imagehash`) |
| `test_google_lens.py` | ~12 | ❌ Import error (missing `imagehash`) |
| `test_gui.py` | ~15 | ❌ Import error (missing `imagehash`) |
| `test_new_case_source_url.py` | ~15 | ❌ Import error (missing `imagehash`) |
| `test_provenance.py` | ~12 | ❌ Import error (missing `imagehash`) |
| `test_reporting.py` | ~10 | ❌ Import error (missing `imagehash`) |
| `test_web_discovery.py` | ~20 | ❌ Import error (missing `imagehash`) |

**Confirmed passing: 23 tests** (audit, case manager, ELA detection, evidence manager)
**Cannot run: 8 test files** due to missing `imagehash` and `rich` packages

### Root Cause
The environment on this machine is missing two critical packages declared in `pyproject.toml`:
- `imagehash>=4.3.0` — used by fingerprinting, provenance, web discovery
- `rich>=13.0.0` — used by CLI

**Fix:** Run `pip install -e ".[dev]"` from the project root (requires `--bypass-sandbox` for network access).

---

## 18. Completed Functionality

All 8 forensic pipeline phases are implemented end-to-end:
1. ✅ Case management (create, list, retrieve)
2. ✅ Evidence vaulting with SHA-256 and read-only enforcement
3. ✅ EXIF/technical metadata extraction
4. ✅ Perceptual hash fingerprinting and comparison
5. ✅ Error Level Analysis (ELA)
6. ✅ Deepfake/synthetic media heuristic assessment
7. ✅ Public URL provenance (SSRF-protected, media similarity, timeline)
8. ✅ Forensic report generation (Markdown, HTML, PDF)
9. ✅ HMAC-chained audit log
10. ✅ Full 8-screen Tkinter GUI with thread-safe background workers
11. ✅ Automated Google Cloud Vision reverse image search
12. ✅ Manual Google Lens investigator-assisted search
13. ✅ Scrapling-powered candidate page enrichment

---

## 19. Incomplete or Partially Implemented Functionality

| Item | Notes |
|---|---|
| `monitoring/` package | Empty stub — no reupload monitoring implemented |
| Screenshot OCR | Specified in PROJECT_SPEC.md, not implemented |
| Video frame search | Code note: "not yet implemented"; session returns `NO_RESULTS` for video |
| Trained ML deepfake detector | Only heuristic baseline; `DetectorType.TRAINED_MODEL` enum exists but unused |
| `evidence metadata` CLI command | MetadataExtractor exists, no CLI binding |
| `discover web`/`discover lens` CLI | Services exist, no CLI bindings |
| SQLite storage option | PROJECT_SPEC mentions SQLite; only JSON implemented |
| File locking in JSONStore | No concurrent-write protection |

---

## 20. Known Bugs and Technical Limitations

| Issue | Severity | Details |
|---|---|---|
| Missing packages in current env | High | `imagehash` and `rich` not installed — 8 test files fail on import |
| Hardcoded student paths | Low | `vision_provider.py` lines 83-84: `C:/Users/student/...` |
| No JSONStore file locking | Medium | Potential data corruption under concurrent writes |
| Windows `os.chmod(0o444)` | Low | Does not guarantee read-only on Windows — owner can still write |
| `.env.example` Claude/ElevenLabs keys | Info | Fake placeholder keys present, not used by application |
| Google Lens `discovery_id` vs `session_id` | Low | `WebDiscoveryWorker` calls `session.discovery_id` but `WebDiscoverySession` uses `session_id` — potential `AttributeError` in `WebDiscoveryWorker.run()` |
| No `case show` command in CLI | Low | `case list` exists but `case show <id>` is referenced in README but missing from `cli/main.py` |

---

## 21. Important Implementation Decisions

1. **Flat JSON files over SQLite**: Simpler to inspect, debug, and version control for academic context.
2. **Pydantic v2 for all models**: Strong validation, auto `model_dump()`, no manual serialisation.
3. **`imagehash` hex strings stored as plain strings**: Enables human inspection and JSON serialisation without custom serialisers.
4. **`DetectorType` enum with HEURISTIC_BASELINE**: Transparency requirement from AGENTS.md — must never imply a trained model.
5. **`fetch_online=False` in GUI source URL path**: When investigator supplies URL at intake, it's recorded as an investigator assertion, not fetched, to avoid SSRF.
6. **Tkinter over PyQt/wx**: No external GUI dependencies; ships with Python stdlib.
7. **Daemon threads**: Worker threads are `daemon=True` so they don't block clean app exit.
8. **`queue.Queue` + `after(100)` polling**: Thread-safe GUI updates without requiring thread-safe Tkinter extensions.
9. **`DIGITALSHIELD_DATA_DIR` env var**: Enables test isolation by pointing to temporary directories.
10. **Dual persistence (JSONStore + case analysis folder)**: Central index for queries + case-local folder for portability/export.

---

## 22. Recommended Next Development Steps

1. **Install missing dependencies**: `pip install imagehash rich` or `pip install -e ".[dev]"` to restore full test suite.
2. **Fix `WebDiscoveryWorker`** `session.discovery_id` → `session.session_id` attribute name inconsistency.
3. **Add `evidence metadata` CLI command** — binds existing `MetadataExtractor` to CLI.
4. **Add `discover web` and `discover lens` CLI commands** — both services fully implemented.
5. **Add `case show` CLI command** — referenced in README, missing from code.
6. **Implement file locking in `JSONStore`** — use `fcntl` (Unix) or `msvcrt.locking` (Windows) for concurrent safety.
7. **Implement `monitoring/` package** — hash-based local reupload detection.
8. **Add Screenshot OCR** — Tesseract-based; planned in spec.
9. **Add video frame extraction** — extract key frames for web discovery.
10. **Integrate a trained deepfake detector** — e.g., ONNX model via `onnxruntime`.
11. **GUI: add `evidence metadata` tab to DetailsScreen** — data already computed by worker.
12. **Remove hardcoded student paths** from `vision_provider.py`.
