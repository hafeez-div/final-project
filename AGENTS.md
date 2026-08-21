# Development Guidelines & Rules for Autonomous Agents and Developers

## 1. Core Ethics & Mission Statement
**DigitalShield** is developed strictly for **defensive digital forensics, victim support, and academic research purposes**. All AI agents, contributors, and automated tooling operating on this repository must rigorously adhere to the ethical boundaries and technical rules detailed below.

---

## 2. Absolute Security & Ethics Guardrails

### 2.1 Prohibited Activities
- **Defensive Focus Only**: This tool exists solely to inspect, verify, preserve, and analyze digital evidence submitted by authorized users.
- **No Hacking / Exploitation**: Never add modules for exploitation, vulnerability probing, brute-forcing, payload delivery, or unauthorized system access.
- **No Credential Theft**: Never implement credential harvesting, keystroke logging, token scraping, or session hijacking features.
- **No Unauthorized Account Access**: Do not attempt to bypass login portals, multi-factor authentication, or platform access controls.
- **No Private Data Extraction**: Never extract private user data without authorization, harvest personal contact lists, or access non-public databases.
- **No Doxxing**: Never search, aggregate, or publish private personal identifiable information (PII) for target harassment or public exposure.
- **No Spyware / Surveillance**: Never implement persistence mechanisms, silent background tracking, hidden surveillance, or unauthorized camera/microphone capture.
- **No Bypassing Platform Restrictions**: Respect platform rate limits, robots.txt, terms of service, and API access rules.

### 2.2 Forensic Integrity & Data Scoping
- **Scope Restriction**: Only analyze user-provided local files and authorized, publicly available information.
- **Evidence Immutability**: **NEVER modify original evidence files**. All operations must be performed on read-only copies or memory buffers. Evidence files must be locked against modification upon ingestion.
- **No Fabricated Findings**: Never synthesize, invent, or falsify forensic metrics, ELA scores, metadata attributes, or deepfake probabilities.
- **Probabilistic AI & ML Output**: All AI model inferences, deepfake scores, and manipulation detection outputs **MUST be explicitly presented as probabilistic assessments** (e.g., probability score, confidence interval, method limitations), never absolute truth.
- **Non-Defamation & Neutrality**: **NEVER claim that an account owner or individual is a criminal or guilty** merely because a username, email, IP address, or handle appears within analyzed evidence. Evidence must be reported neutrally and factually.

---

## 3. Credentials, Secrets & Privacy Safeguards
- **No Hard-Coded API Keys**: Never hard-code API tokens, passwords, database credentials, or secret keys in source files or tests.
- **Environment Configuration**: Use `.env` templates (e.g., `.env.example`) and OS environment variable lookup mechanisms only.
- **No Secrets or Victim Evidence in Version Control**: Never commit real victim data, personal photos, private case files, or live API credentials into git repositories. All test fixtures must use synthetic or public domain sample data.

---

## 4. Software Engineering & Development Practices

### 4.1 Test-Driven & Verified Code
- **Module Test Requirement**: Every module, feature, or utility must be accompanied by comprehensive unit and integration tests.
- **Incremental Building**: Build the system incrementally in small, discrete, fully tested increments.
- **Preserve Existing Code**: Do not rewrite unrelated, working codebase modules. Refactor only when necessary and with test coverage validation.
- **Run Tests After Every Stage**: Execute the test suite after completing every implementation task or module before moving to the next.

---

## 5. Summary Checklist for AI Agents
Before completing any task or pull request, verify:
- [ ] Are all original evidence files treated as read-only?
- [ ] Are all AI and detection outputs documented with probabilistic scores/limitations?
- [ ] Is there zero offensive or credential-harvesting code included?
- [ ] Are all API keys and secrets stored outside the codebase?
- [ ] Did you add automated tests for newly added functions?
- [ ] Did all unit and integration tests pass successfully?
