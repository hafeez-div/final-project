# DigitalShield Technical Architecture

## Modular Subsystem Layout

```
digitalshield/
├── cli/             Entry point and user interaction (CLI) layer
├── case_manager/    Case lifecycle, metadata, and state management
├── evidence/        Ingestion engine, SHA-256 hash baseline, read-only evidence vault
├── detection/       Manipulation analysis, Error Level Analysis (ELA), deepfake scoring
├── metadata/        Technical headers, EXIF parser, metadata anomaly flags
├── fingerprinting/  Perceptual hashing (aHash, pHash, dHash) & similarity indexing
├── provenance/      Authorized web snapshot records & origin timeline mapping
├── monitoring/      Local reupload checks & matching against index feeds
├── reporting/       Markdown/HTML/PDF report builders with cryptographic manifests
├── storage/         Local SQLite database & structured persistence
└── security/        Append-only audit logs with cryptographic entry signatures
```

## Data Flow & Forensic Pipeline

1. **Ingestion & Vaulting**: Evidence is received via `evidence/`, SHA-256 hashed, stored in read-only vaults, and recorded in `storage/`.
2. **Analysis Execution**: `detection/`, `metadata/`, and `fingerprinting/` plugins analyze read-only buffers without modifying source files.
3. **Audit Trail**: All events log directly through `security/` to maintain immutable chain-of-custody logs.
4. **Report Export**: `reporting/` packages case details, verification hashes, probabilistic AI scores, and timestamps into verifiable audit reports.
