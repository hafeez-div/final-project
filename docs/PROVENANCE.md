# DigitalShield Public URL Provenance Subsystem

## Overview
The **Public URL Provenance** subsystem (Phase 7) enables digital forensics investigators to record publicly available web observation data, extract public metadata, and perform perceptual visual similarity comparisons between public media assets and registered evidence in the vault.

## Ethical & Security Boundaries

### Defensive Scope Only
- **Zero Authentication / Private Access**: Operates strictly on publicly accessible HTTP/HTTPS resources. Never attempts login bypass, token reuse, private account scraping, or credential collection.
- **SSRF Controls**:
  - Validates all target URLs against `http://` and `https://` schemes.
  - Rejects `localhost`, loopback addresses (`127.0.0.1`, `::1`), private IPv4 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local IPs (`169.254.0.0/16`), and reserved IP spaces.
  - Resolves target hostnames to IP addresses prior to HTTP requests.
  - Enforces socket timeouts (10 seconds) and byte response limits (5 MB).
  - Validates redirected URLs against SSRF filters before following.
- **Neutral Attribution Phrasing**:
  - Uses strictly neutral terminology (*"Reported source"*, *"Observed account"*, *"Publicly observed source"*, *"Investigative lead"*, *"Evidence-supported association"*).
  - Never claims that an account owner uploaded an image, created media, or is guilty/responsible.

## Architectural Integration
- **Storage**: Provenance records are stored as derived analysis in `.digitalshield_data/provenance.json` and `.digitalshield_data/cases/<case_id>/analysis/provenance_<provenance_id>.json`.
- **Perceptual Hashing**: Reuses Phase 4 `FingerprintService` to compute normalized Hamming distance similarity across aHash, dHash, and pHash algorithms.
- **Audit Trails**: Logs `PROVENANCE_SOURCE_RECORDED` and `PROVENANCE_MEDIA_MATCHED` via `AuditLogger`.

## CLI Usage

```bash
# Record a public URL provenance observation
python -m digitalshield provenance add EVD-2026-000001 https://example.com/post/123 --account "public_user" --media-url https://example.com/image.png

# List provenance records in a case
python -m digitalshield provenance list --case DS-2026-000001

# Show detailed provenance record
python -m digitalshield provenance show PRV-2026-000001

# Generate origin timeline for an evidence item
python -m digitalshield provenance timeline EVD-2026-000001
```
