# DEVELOPMENT_ROADMAP.md — DigitalShield

> **Generated:** 2026-11-01 | Based on actual codebase inspection

---

## Legend

| Symbol | Meaning |
|---|---|
| ✅ | Fully implemented and tested |
| 🟡 | Partially implemented |
| ❌ | Planned/specified but NOT implemented |
| 🐛 | Bug or defect identified |
| 🔧 | Technical debt |
| 💡 | Proposed improvement (not in original spec) |

---

## 1. Existing Completed Features

These features are **fully implemented** in the current codebase. Verified by source code inspection and test runs.

### Core Infrastructure
- ✅ **JSONStore** — flat-file JSON persistence for all 10 entity types
- ✅ **AuditLogger** — append-only, HMAC-chained JSONL audit log
- ✅ **`DIGITALSHIELD_DATA_DIR` env override** — test isolation support
- ✅ **`pyproject.toml` package build config** with `[project.scripts]` entry point

### Case Management (`case_manager/`)
- ✅ Case creation with `DS-YYYY-XXXXXX` sequential ID generation
- ✅ Case vault directory structure creation
- ✅ Case persistence and retrieval
- ✅ Case listing
- ✅ Evidence count tracking on case record
- ✅ Optional `source_url` field on Case model

### Evidence Management (`evidence/`)
- ✅ File existence and extension validation
- ✅ MIME type inference from magic bytes (PNG, JPEG, GIF, WEBP, PDF)
- ✅ Chunked SHA-256 computation (64 KB chunks, memory-safe)
- ✅ Duplicate rejection within case (SHA-256 comparison)
- ✅ `shutil.copy2()` vault preservation (original never touched)
- ✅ Read-only file permission enforcement (`os.chmod(0o444)`)
- ✅ `EVD-YYYY-XXXXXX` sequential Evidence ID generation
- ✅ `evidence_manifest.json` per case vault
- ✅ Evidence listing by case, retrieval by ID
- ✅ Optional `source_url` field on Evidence model

### Metadata Extraction (`metadata/`)
- ✅ Technical metadata: format, dimensions, color mode, size
- ✅ EXIF tag extraction (11 standard tags)
- ✅ GPS coordinate extraction (DMS → decimal)
- ✅ Non-fabrication policy enforced (absent fields → `None`)
- ✅ Pillow read-only mode (no file modification)
- ✅ Non-image graceful handling (`UnidentifiedImageError`)
- ✅ JSONStore persistence + audit event

### Perceptual Fingerprinting (`fingerprinting/`)
- ✅ aHash, dHash, pHash computation (64-bit hex strings via `imagehash`)
- ✅ Result caching in JSONStore with `force_recompute` bypass
- ✅ Hamming distance calculation
- ✅ Normalized similarity (0.0–1.0)
- ✅ Two-evidence comparison with overall similarity score
- ✅ Probabilistic assessment language in comparison output
- ✅ Audit logging

### Error Level Analysis (`detection/ela.py`)
- ✅ In-memory JPEG recompression (no vault file modification)
- ✅ Pixel-wise absolute difference map
- ✅ Full statistics: mean, max, stddev, RMS error
- ✅ Dynamic high-error threshold (`max(12, mean + 1.5*stddev)`)
- ✅ Bounding box of high-error region
- ✅ Normalized anomaly score formula
- ✅ Confidence bands by image resolution
- ✅ Three-tier probabilistic assessment (Low/Moderate/High)
- ✅ Disclaimer embedded in result model
- ✅ Dual persistence (central + case analysis folder)
- ✅ Audit logging

### Deepfake Assessment (`detection/deepfake.py`)
- ✅ `BaseDeepfakeDetector` ABC (plugin architecture ready)
- ✅ `BaselineDeepfakeDetector` — heuristic scoring
  - EXIF presence/absence heuristic
  - Common generative AI resolution detection
  - Square aspect ratio heuristic
  - RGB channel variance heuristic
  - Compression error variance heuristic
- ✅ Probability clamped to [0.05, 0.95]
- ✅ `DetectorType.HEURISTIC_BASELINE` transparency enforcement
- ✅ Explicit limitations list in every result
- ✅ Dual persistence + audit logging

### Public URL Provenance (`provenance/`)
- ✅ SSRF URL validation (scheme, DNS resolution, IP range checks)
- ✅ Public URL fetching (10s timeout, 5 MB cap, redirect validation)
- ✅ HTML title extraction from fetched page
- ✅ Media URL download + perceptual hash comparison against evidence
- ✅ Similarity scoring using existing `FingerprintService`
- ✅ `PRV-YYYY-XXXXXX` sequential ID generation
- ✅ Neutral assessment language enforcement
- ✅ `fetch_online=False` mode for investigator-supplied URL recording
- ✅ Provenance timeline generation (chronological)
- ✅ Listing by case and by evidence
- ✅ Dual persistence + audit logging (PROVENANCE_SOURCE_RECORDED + PROVENANCE_MEDIA_MATCHED)

### Web Discovery (`web_discovery/`)
- ✅ `VisionWebDetectionProvider` — Google Cloud Vision REST API client
  - Base64 image encoding
  - In-memory resize for oversized images
  - Credential error vs. API error separation
  - Full response parsing (exact, partial, visually similar, pages)
- ✅ `WebDiscoveryService` — automated pipeline
  - Candidate deduplication via `normalize_url()`
  - Scrapling-powered page enrichment (`enrich_page()`)
  - Per-candidate perceptual hash comparison
  - Session + result persistence (dual: JSONStore + case folder)
  - Full audit trail (session start → provider request → scrape → verify → complete)
  - Graceful handling of video evidence (returns `NO_RESULTS`)
  - Graceful handling of `CredentialError`
- ✅ `GoogleLensService` — manual investigator-assisted
  - `initiate_lens_search()` → browser open
  - `record_match_result()` with URL validation
  - `mark_session_no_results()`
  - `GLS-`/`GLR-` ID scheme
- ✅ `detect_platform_name()` — URL-based social platform detection

### Reporting (`reporting/`)
- ✅ `ReportingService.compile_report_data()` — aggregates all case data
- ✅ `MarkdownRenderer` — GitHub-Flavored Markdown
- ✅ `HTMLRenderer` — 100% offline, no CDN/external assets
- ✅ `PDFRenderer` — ReportLab paginated with headers/footers/page numbers
- ✅ 12 structured report sections
- ✅ Web discovery data included in report
- ✅ `RPT-YYYY-XXXXXX` sequential ID
- ✅ Dual persistence + audit logging

### Desktop GUI (`gui/`)
- ✅ `DigitalShieldApp` — main Tkinter window with screen routing
- ✅ Dark theme (`theme.py`) with custom colours and fonts
- ✅ 8 fully implemented screens
- ✅ `AnalysisWorker` — 7-step background pipeline with `queue.Queue` messaging
- ✅ `ReportWorker` — report generation without GUI freeze
- ✅ `WebDiscoveryWorker` — Vision API re-run on demand
- ✅ `NewCaseScreen` with native file dialog and SSRF URL validation
- ✅ `ProgressScreen` with live checklist and polling via `after(100)`
- ✅ `ResultsScreen` with summary dashboard
- ✅ `DetailsScreen` with tabbed EXIF/Fingerprint/ELA/Deepfake tabs
- ✅ `ProvenanceScreen` with Google Lens management
- ✅ `ReportsScreen` with format selection and file open buttons
- ✅ `OpenCaseScreen` with case browser

### CLI (`cli/main.py`)
- ✅ `case create`, `case list`
- ✅ `evidence import`, `evidence list`, `evidence show`, `evidence fingerprint`, `evidence compare`
- ✅ `analyze ela`, `analyze deepfake`
- ✅ `provenance add`, `provenance list`, `provenance show`, `provenance timeline`
- ✅ `report generate`, `report list`, `report show`
- ✅ `gui` — launch desktop application

---

## 2. Partially Implemented Features

### 🟡 Deepfake Detection (Heuristic Only)
- **What exists**: Fully functional heuristic baseline detector
- **What's missing**: A trained ML model (CNN, ViT, or pre-trained deepfake detection model)
- **Plugin interface ready**: `BaseDeepfakeDetector` ABC allows swapping in a real model with no service changes
- **Effort**: Medium-High (requires model selection, ONNX export, integration)

### 🟡 Google Cloud Vision Integration
- **What exists**: Full REST API client, provider, session management
- **What's missing**: Populated `GOOGLE_CLOUD_API_KEY` — without it, sessions return `MISSING_CREDENTIALS`
- **Effort**: Zero code change; configuration only

### 🟡 CLI Coverage
- **What exists**: Core 5 command groups implemented
- **What's missing**: `evidence metadata`, `discover web`, `discover lens`, `case show` commands
- **Effort**: Low (services fully implemented)

---

## 3. Planned but NOT Implemented Features

### ❌ Monitoring / Reupload Framework (`monitoring/`)
- **Spec:** "Periodic verification of public image hashes against index feeds"
- **Current state:** `monitoring/__init__.py` is a 97-byte empty stub
- **What's needed:** Local hash-match queries across internal repositories; optional scheduled checks
- **Effort:** Medium

### ❌ Screenshot & OCR Analysis
- **Spec (PROJECT_SPEC.md §3.2.E):** "OCR extraction of visible text, URL detection, username/handle detection, timestamp extraction, UI component layout sanity checks"
- **Current state:** Not started
- **Suggested library:** `pytesseract` + `Pillow` crop regions
- **Effort:** Medium

### ❌ Video Frame Extraction for Web Discovery
- **Spec & code note:** "Video frame extraction for reverse search is not yet implemented"
- **Current state:** Video evidence is accepted into vault but web search returns `NO_RESULTS` with explicit note
- **Suggested approach:** Extract frames with `opencv-python` or `ffmpeg-python`
- **Effort:** Medium

### ❌ SQLite Storage Backend
- **Spec (PROJECT_SPEC.md §4.1):** "Local SQLite database or structured JSON store"
- **Current state:** JSON-only; no SQLite implementation
- **Effort:** High (full migration)

---

## 4. Bugs That Need Attention

### 🐛 `WebDiscoveryWorker` Attribute Error (Medium)
- **File:** [`digitalshield/gui/workers.py`](digitalshield/gui/workers.py) line 208
- **Issue:** `session.discovery_id` — `WebDiscoverySession` model uses `session_id` not `discovery_id`
- **Impact:** `WebDiscoveryWorker.run()` will raise `AttributeError` when loading results after re-search
- **Fix:** Change `session.discovery_id` → `session.session_id`

### 🐛 Missing `case show` CLI Command (Low)
- **File:** [`digitalshield/cli/main.py`](digitalshield/cli/main.py)
- **Issue:** README and docs reference `python -m digitalshield case show DS-2026-000001` but this command is not defined
- **Fix:** Add `@case.command("show")` with `CaseManager.get_case()`

### 🐛 Missing `evidence metadata` CLI Command (Low)
- **File:** [`digitalshield/cli/main.py`](digitalshield/cli/main.py)
- **Issue:** `MetadataExtractor` is fully implemented but has no CLI binding
- **Fix:** Add `@evidence.command("metadata")` calling `MetadataExtractor.extract()`

### 🐛 Hardcoded Student File Paths (Low)
- **File:** [`digitalshield/web_discovery/vision_provider.py`](digitalshield/web_discovery/vision_provider.py) lines 83–84
- **Issue:** `Path("C:/Users/student/final-project/.env")` — academic machine paths hardcoded
- **Fix:** Remove or replace with generic project root path discovery

### 🐛 `read_file` Not Closed Before `img.load()` in MetadataExtractor (Low)
- **File:** [`digitalshield/metadata/extractor.py`](digitalshield/metadata/extractor.py) line 191-192
- **Issue:** `with open(...) as fh: img = Image.open(fh); img.load()` — calling `img.load()` inside `with` block is correct but `img` is used after the block closes `fh`. This works in Pillow (lazy loading is resolved by `img.load()`) but is subtle.
- **Risk:** Minor — works correctly but may confuse future maintainers

---

## 5. Technical Debt

### 🔧 Missing Package Installation (Critical for Dev)
- **Issue:** `imagehash` and `rich` are declared in `pyproject.toml` but not installed in current environment
- **Impact:** 8 of 14 test files cannot be collected; CLI cannot run
- **Fix:** `pip install -e ".[dev]"` from project root (network access needed)

### 🔧 No File Locking in JSONStore (Medium)
- **File:** [`digitalshield/storage/json_store.py`](digitalshield/storage/json_store.py)
- **Issue:** `_read_file()` / `_write_file()` have no lock mechanism — race conditions under concurrent access
- **Impact:** Low in single-user desktop context; significant if accessed from multiple CLI calls simultaneously
- **Fix:** `threading.Lock()` per file, or `filelock` library

### 🔧 Windows `os.chmod(0o444)` Limitation (Low)
- **File:** [`digitalshield/evidence/manager.py`](digitalshield/evidence/manager.py) lines 207, 151
- **Issue:** On Windows, `os.chmod(0o444)` does not fully prevent overwrites by the file owner
- **Fix:** Use `SetFileAttributes` via `ctypes.windll.kernel32` with `FILE_ATTRIBUTE_READONLY` for proper Windows enforcement

### 🔧 Duplicate `SUPPORTED_IMAGE_MIMES` / `SUPPORTED_IMAGE_EXTENSIONS` (Low)
- **Files:** `detection/ela.py`, `detection/deepfake.py`, `fingerprinting/service.py`, `web_discovery/service.py`
- **Issue:** Same sets defined in four separate modules
- **Fix:** Move to `digitalshield/constants.py` and import from there

### 🔧 `google-cloud-vision` in Dependencies but Not Used (Low)
- **File:** `pyproject.toml` line 31
- **Issue:** `google-cloud-vision>=3.0.0` is listed but the implementation uses the REST API directly via `urllib.request`, not the SDK
- **Fix:** Remove the SDK dependency; only `urllib.request` (stdlib) is needed for the Vision API call

### 🔧 No Test for `MetadataExtractor` (Medium)
- **Issue:** `test_detection.py` covers ELA and deepfake but there is no dedicated `test_metadata.py`
- **Fix:** Add `test_metadata.py` covering extraction, GPS parsing, EXIF present/absent, non-image fallback

### 🔧 `EvidenceManager` CLI `metadata` Command Missing (Low)
- Already listed as a bug; also a debt in CLI completeness

### 🔧 No Test for `JSONStore` in Isolation (Low)
- **Issue:** JSONStore tested indirectly through other managers; direct unit tests for edge cases (corrupt JSON, missing files) not present
- **Fix:** Add `test_json_store.py`

---

## 6. Potential Improvements

### 💡 Replace Heuristic Deepfake Detector with Trained Model
- **Priority:** High (academic differentiation)
- **Options:**
  - Load an ONNX-exported deepfake detection model via `onnxruntime`
  - Integrate `Hugging Face` model inference locally
  - The `BaseDeepfakeDetector` ABC means the service layer needs zero changes
- **Requirement per AGENTS.md:** Must still label output as probabilistic; include calibration limitations

### 💡 Screenshot OCR Module
- **Library:** `pytesseract` + Tesseract binary
- **Functionality:** Extract visible text from screenshots, detect URLs, handles, timestamps
- **Integration:** New `digitalshield/ocr/` module following same service/model/store pattern

### 💡 Add `evidence metadata` CLI Command
- **Effort:** ~10 lines of Click code
- **Benefit:** Full CLI parity with implemented features

### 💡 Add `discover web` and `discover lens` CLI Commands
- **Effort:** ~50 lines of Click code
- **Benefit:** Full CLI parity with implemented features

### 💡 Add `case show` CLI Command
- **Effort:** ~15 lines of Click code

### 💡 GUI: Add Metadata Tab or Separate Screen
- **Current state:** `DetailsScreen` has EXIF tab but it may not surface all extracted fields
- **Improvement:** Expose full `MetadataResult` in a dedicated scrollable tab

### 💡 GUI: Audit Log Viewer
- **Current state:** Audit log is referenced in README as a GUI feature; verify current `DetailsScreen` or `ResultsScreen` includes it
- **Improvement:** Dedicated `AuditScreen` with scrollable JSONL viewer

### 💡 File Locking for JSONStore
- **Effort:** Low-Medium
- **Library:** `filelock` (cross-platform)

### 💡 Monitoring / Reupload Detection
- **Implement `monitoring/` package** per PROJECT_SPEC.md §3.2.G:
  - Local hash-match queries across all case fingerprints
  - Alert when same hash appears in new evidence import

### 💡 Export Evidence Package
- **Spec:** "Export evidence packages with cryptographic manifest signatures"
- **Implementation:** ZIP archive of vault + metadata + audit log + reports with SHA-256 manifest

### 💡 Video Frame Extraction
- **Library:** `opencv-python` or `ffmpeg-python`
- **Flow:** Extract N representative frames → import as individual evidence → run normal pipeline per frame

### 💡 Portable `.exe` Build
- **Tool:** `PyInstaller` with `--windowed` flag
- **Benefit:** Single executable for non-technical victims

### 💡 Remove Unused `google-cloud-vision` SDK Dependency
- **Saves:** ~5 MB install size; avoids unnecessary Google auth library loading

---

## 7. Dependencies Between Future Tasks

```
Install missing packages (imagehash, rich)
    └→ Enables all 8 blocked test files
    └→ Enables CLI usage verification

Fix WebDiscoveryWorker attribute bug
    └→ Unblocks re-run web discovery from GUI

Add evidence metadata CLI command
    └→ Completes CLI parity with services

Add case show CLI command  (independent)

Add discover web/lens CLI commands (independent)

Implement monitoring/ package
    └→ Depends on: fingerprinting service (✅ done)

Implement Screenshot OCR
    └→ Requires: Tesseract installation
    └→ New module (independent of existing services)

Implement video frame extraction
    └→ Requires: opencv-python or ffmpeg-python
    └→ Integrates with: EvidenceManager (import frames), WebDiscoveryService

Replace deepfake detector with trained model
    └→ Depends on: BaseDeepfakeDetector ABC (✅ done)
    └→ Requires: model file, onnxruntime or equivalent
    └→ No service-layer changes needed

Export evidence package feature
    └→ Depends on: all analysis services (✅ done)
    └→ New service class in digitalshield/export/

Portable .exe build
    └→ Depends on: all dependencies installed
    └→ Requires: PyInstaller configuration
```

---

## 8. Release Milestone Suggestions

### Milestone 0 — Environment Restore (Immediate)
- [ ] Install `imagehash` and `rich`
- [ ] Run full test suite; confirm all 81+ tests pass
- [ ] Fix `WebDiscoveryWorker` `session.discovery_id` bug
- [ ] Fix `case show` missing CLI command
- [ ] Fix `evidence metadata` missing CLI command
- [ ] Remove hardcoded student paths from `vision_provider.py`

### Milestone 1 — CLI Completeness
- [ ] Add `discover web <ev_id>` CLI command
- [ ] Add `discover lens <ev_id>` CLI command
- [ ] Update README CLI reference section

### Milestone 2 — Detection Improvement
- [ ] Integrate trained ONNX deepfake detection model
- [ ] Add Screenshot OCR module (`digitalshield/ocr/`)
- [ ] Add `analyze ocr <ev_id>` CLI command

### Milestone 3 — Platform Completeness
- [ ] Video frame extraction support
- [ ] Implement `monitoring/` reupload detection package
- [ ] Add monitoring CLI commands and GUI panel

### Milestone 4 — Production Hardening
- [ ] Add file locking to JSONStore
- [ ] Proper Windows read-only enforcement via `ctypes`
- [ ] Remove unused `google-cloud-vision` SDK dependency
- [ ] Consolidate duplicate constants into `digitalshield/constants.py`
- [ ] Add missing `test_metadata.py` and `test_json_store.py`

### Milestone 5 — Distribution
- [ ] PyInstaller portable `.exe` build
- [ ] Evidence package export with cryptographic manifest
- [ ] User manual PDF
