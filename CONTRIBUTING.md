# Contributing to DigitalShield

Thank you for contributing to **DigitalShield**.

## Strict Rules of Engagement

Before submitting code or pull requests, you must read and agree to follow all guidelines in [`AGENTS.md`](AGENTS.md):

1. **Defensive Purpose Only**: No offensive tools, credential harvesting, or exploitation capabilities will be accepted.
2. **Read-Only Evidence Safeguards**: Any module touching evidence must respect read-only file locks and compute SHA-256 hashes without modifying source files.
3. **Probabilistic AI Outputs**: Models or detection functions must return probabilistic scores and limitations rather than absolute claims.
4. **Secrets and Privacy**: Never commit real victim data, photos, or API credentials. Use synthetic fixtures in `tests/`.
5. **Test Requirements**: All pull requests must include comprehensive unit and integration tests under `tests/`.

---

## Development Workflow

1. Fork/branch the repository.
2. Ensure Python 3.11+ is active.
3. Install dependencies: `pip install -e .[dev]`.
4. Write tests for new functionality before/alongside code.
5. Run the test suite: `pytest`.
6. Ensure zero test failures before submitting a PR.
