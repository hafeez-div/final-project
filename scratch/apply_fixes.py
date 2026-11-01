import os

# 1. Update service.py
service_path = "digitalshield/web_discovery/service.py"
with open(service_path, "r", encoding="utf-8") as f:
    service_code = f.read().replace("\r\n", "\n")

# Add _result_status if not present
if "def _result_status" not in service_code:
    # insert before _compare_remote_image
    target = "    def _compare_remote_image("
    replacement = """    @staticmethod
    def _result_status(match_type: str, score: Optional[float] = None) -> str:
        if match_type in ("EXACT_MATCH", "PARTIAL_MATCH"):
            return "Source discovered"
        if match_type == "VISUALLY_SIMILAR":
            return "Potential media match"
        return "Awaiting investigator review"

    def _compare_remote_image("""
    service_code = service_code.replace(target, replacement, 1)

# Add audit events for WEB_DISCOVERY
if "WEB_DISCOVERY_SESSION_STARTED" not in service_code:
    service_code = service_code.replace(
        'actor="DigitalShield Automation Engine",\n        )',
        'actor="DigitalShield Automation Engine",\n        )\n        self.audit_logger.log_event(\n            action="WEB_DISCOVERY_SESSION_STARTED",\n            details={"session_id": session_id, "evidence_id": evidence_id, "case_id": evidence.case_id},\n            actor="DigitalShield Automation Engine",\n        )',
        1
    )

if "WEB_DISCOVERY_COMPLETED" not in service_code:
    service_code = service_code.replace(
        'action="REVERSE_SEARCH_COMPLETED",',
        'action="REVERSE_SEARCH_COMPLETED",\n        )\n        self.audit_logger.log_event(\n            action="WEB_DISCOVERY_COMPLETED",\n            details={"session_id": session_id, "evidence_id": evidence_id, "case_id": evidence.case_id},\n            actor="DigitalShield Web Discovery Service",\n        )\n        self.audit_logger.log_event(\n            action="REVERSE_SEARCH_COMPLETED_ALIAS",',
        1
    )
    # clean up the dummy alias line
    service_code = service_code.replace('action="REVERSE_SEARCH_COMPLETED_ALIAS",\n            details=', 'action="REVERSE_SEARCH_COMPLETED",\n            details=')

if "WEB_DISCOVERY_CREDENTIAL_ERROR" not in service_code:
    service_code = service_code.replace(
        'action="REVERSE_SEARCH_FAILED",\n                details={\n                    "case_id": evidence.case_id,\n                    "session_id": session_id,\n                    "evidence_id": evidence_id,\n                    "error": str(pe)[:250],\n                },\n                actor="DigitalShield Web Discovery Service",\n            )',
        'action="REVERSE_SEARCH_FAILED",\n                details={\n                    "case_id": evidence.case_id,\n                    "session_id": session_id,\n                    "evidence_id": evidence_id,\n                    "error": str(pe)[:250],\n                },\n                actor="DigitalShield Web Discovery Service",\n            )\n            self.audit_logger.log_event(\n                action="WEB_DISCOVERY_CREDENTIAL_ERROR" if ("key" in str(pe).lower() or "credential" in str(pe).lower()) else "WEB_DISCOVERY_FAILED",\n                details={\n                    "case_id": evidence.case_id,\n                    "session_id": session_id,\n                    "evidence_id": evidence_id,\n                    "error": str(pe)[:250],\n                },\n                actor="DigitalShield Web Discovery Service",\n            )'
    )

with open(service_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(service_code)

print("Updated service.py")

# 2. Update test_web_discovery.py
test_path = "tests/test_web_discovery.py"
with open(test_path, "r", encoding="utf-8") as f:
    test_code = f.read().replace("\r\n", "\n")

test_code = test_code.replace(
    '"provider": "Google Cloud Vision Web Detection"',
    '"provider": "Google Lens"'
)

test_code = test_code.replace(
    'assert "Public Image / Video Source Discovery" in md',
    'assert "Public Online Image Discovery and Reverse Image Search Findings" in md'
)
test_code = test_code.replace(
    'assert "Google Cloud Vision Web Detection" in md',
    'assert "Google Lens" in md'
)
test_code = test_code.replace(
    'assert "Public Image / Video Source Discovery" in html',
    'assert "Public Online Image Discovery and Reverse Image Search Findings" in html'
)
test_code = test_code.replace(
    'found = any("Web Detection" in f or "web discovery" in f.lower() for f in data.overall_findings)',
    'found = any("reverse search" in f.lower() or "image discovery" in f.lower() or "web discovery" in f.lower() for f in data.overall_findings)'
)

with open(test_path, "w", encoding="utf-8", newline="\n") as f:
    f.write(test_code)

print("Updated test_web_discovery.py")
