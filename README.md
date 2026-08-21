# DigitalShield

> **Defensive Digital Forensics, Evidence Preservation, and Verification Suite**

DigitalShield is an academic final-year project designed for defensive digital forensics, evidence integrity verification, media manipulation analysis, and victim support. It provides a CLI-based workflow for creating cases, ingesting and hashing evidence, performing forensic checks, and generating verifiable reporting packages.

---

## Architecture & Design Principles

DigitalShield follows a strict modular structure adhering to defensive ethics and forensic data integrity:

```
DigitalShield/
├── digitalshield/
│   ├── cli/             # Command-Line Interface entrypoints and commands
│   ├── case_manager/    # Case lifecycle and case metadata administration
│   ├── evidence/        # Evidence ingestion, SHA-256 hashing & read-only vaults
│   ├── detection/       # Forensics & image manipulation detection interface
│   ├── metadata/        # Technical metadata and EXIF extraction
│   ├── fingerprinting/  # Perceptual hashing & visual similarity matching
│   ├── provenance/      # Public provenance analysis and web snapshot records
│   ├── monitoring/      # Reupload verification and index matching
│   ├── reporting/       # Forensic report generation (MD/HTML/PDF)
│   ├── storage/         # Secure local data persistence
│   └── security/        # Immutable audit logging & credentials safety
├── tests/               # Test suites (unit & integration)
├── docs/                # Project documentation & guides
├── PROJECT_SPEC.md      # Functional requirements specification
└── AGENTS.md            # Strict ethical rules and development guidelines
```

---

## Ethical & Security Guardrails

All operations within DigitalShield adhere to strict rules defined in [`AGENTS.md`](AGENTS.md):
- **Defensive Focus Only**: Developed exclusively for investigation, evidence verification, and victim support.
- **Evidence Immutability**: Evidence files are ingested into read-only vaults and hashed with SHA-256 upon entry.
- **Probabilistic Assessments**: AI/ML outputs are documented with explicit probability scores and limitations.
- **No Unauthorized Access**: Strictly no exploitation, credential theft, bypassing authentication, or scraping private data.

---

## Installation & Setup

Requires **Python 3.11+**.

```bash
# Clone repository
git clone https://github.com/example/DigitalShield.git
cd DigitalShield

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install editable package with dev dependencies
pip install -e .[dev]
```

---

## Development & Verification

Run tests using `pytest`:

```bash
pytest
```

---

## License

MIT License. See [`LICENSE`](LICENSE) for details.
