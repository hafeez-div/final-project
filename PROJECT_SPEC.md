# Project Specification: DigitalShield

## 1. Executive Summary & Overview
**DigitalShield** is a terminal/CLI-based digital forensics and evidence management system developed in Python for academic research, digital investigation, and cybercrime defense context. The system provides a standardized workflow for importing, preserving, analyzing, and documenting digital evidence (such as images, video frames, documents, and screenshots) while maintaining strict forensic integrity and chain of custody.

---

## 2. Core Technical Architecture
- **Language**: Python 3.10+
- **Interface**: Terminal / Command Line Interface (CLI) with interactive prompts, rich formatting, and scriptable subcommands.
- **Core Principles**: Read-only evidence handling, cryptographic verification, modular forensic analysis plugins, transparent audit trails, local storage security.

---

## 3. Functional Requirements

### 3.1 Case & Evidence Management
- **Case Creation**: 
  - Initialize forensic cases with unique Case ID, Case Name, Investigator Info, Description, and Timestamp.
  - Create directory structures with strict local access controls.
- **Evidence Import**:
  - Support single file and batch folder ingestion.
  - Automatically assign unique Evidence IDs and maintain original filename and ingestion timestamps.
- **Evidence Preservation & Cryptographic Integrity**:
  - Automatically create read-only evidence vaults.
  - Calculate dual/multi hashes upon import (SHA-256 mandatory, MD5/SHA-1 optional for legacy reference).
  - Continuous integrity verification against initial hash baseline.

### 3.2 Forensic Analysis Modules

#### A. Metadata & EXIF Extraction
- Extract technical metadata (File size, MIME type, dimensions, headers, creation/modification dates).
- Extract embedded EXIF data (Camera model, software version, shutter speed, ISO, GPS coordinates if present).
- Detect metadata anomalies, missing headers, or software editing signatures (e.g., Photoshop, GIMP artifacts).

#### B. Perceptual Hashing & Similarity Matching
- Compute perceptual hashes (aHash, pHash, dHash) for media assets.
- Build similarity index to detect duplicate or near-duplicate media files despite resizing or compression.

#### C. Image Manipulation Analysis
- Error Level Analysis (ELA) to detect resaved regions and JPEG compression inconsistencies.
- Noise pattern variance inspection and clone/copy-move detection heuristics.
- Color space / luminance anomaly flags.

#### D. Deepfake & Synthetic Content Assessment
- Statistical analysis of facial regions, texture consistency, and frame boundary artifacts.
- Probabilistic scoring models for synthetic image/video detection.
- Clear reporting of confidence intervals with probabilistic caveats.

#### E. Screenshot & OCR Analysis
- Optical Character Recognition (OCR) extraction of visible text from screenshots (chat logs, social media posts, web pages).
- Text pattern matching (URL detection, username/handle detection, timestamp extraction).
- UI component layout sanity checks to flag fabricated screenshot overlays.

#### F. Public URL & Provenance Analysis
- Capture authorized public web page metadata, headers, domain WHOIS (where public), and HTTP response status.
- Generate web archive snapshot records with SHA-256 digest of retrieved HTML/assets.
- Map content origin timelines across public sources without bypassing authentication.

#### G. Reupload & Monitoring Framework
- Local hash match queries across internal case repositories.
- Periodic verification of public image hashes against index feeds (where public APIs exist).

### 3.3 Reporting & Export
- **Complaint & Incident Report Generation**:
  - Generate comprehensive Markdown, HTML, and PDF summary reports.
  - Include Case details, Chain of Custody, Hash Verification table, Analysis summaries, and Visual breakdown.
- **Standardized Legal/Forensic Export**:
  - Export evidence packages with cryptographic manifest signatures.

---

## 4. Security, Privacy & Storage

### 4.1 Storage & Encryption
- Store case data in local SQLite database or structured JSON store with file-level cryptographic verification.
- Sensitive investigator inputs or API keys stored strictly via local environment variables or OS keyrings.

### 4.2 Audit Logging & Chain of Custody
- Append-only audit log tracking every user action, module execution, CLI flag, and verification event.
- Immutable log entry hashing to detect log tampering.

---

## 5. Testing & Verification Requirements
- **Unit Tests**: Minimum 85% test coverage across core forensic logic.
- **Integration Tests**: End-to-end case import, analysis pipeline, hash verification, and report rendering test suite.
- **Forensic Validation Tests**: Verification against standard test corpora (e.g., modified vs authentic image datasets).

---

## 6. Documentation Requirements
- User Manual & CLI Command Reference.
- Developer API guide for extending analysis plugins.
- Forensic Integrity & Chain-of-Custody compliance guide.
