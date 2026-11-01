import os
import sys
import json
import hashlib
from pathlib import Path

sys.path.insert(0, "c:/Users/hp/Desktop/final-project")
os.chdir("c:/Users/hp/Desktop/final-project")

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

from dotenv import load_dotenv
load_dotenv(Path("c:/Users/hp/Desktop/final-project/.env"))

from digitalshield.evidence.manager import EvidenceManager
from digitalshield.web_discovery.service import WebDiscoveryService
from digitalshield.provenance.client import SafePublicClient
from digitalshield.reporting.service import ReportingService

base_dir = Path(".digitalshield_data")
ev_mgr = EvidenceManager(base_dir=base_dir)
client = SafePublicClient(timeout=3)
wds = WebDiscoveryService(base_dir=base_dir, client=client)
rep_svc = ReportingService(base_dir=base_dir)

ev_id = "EVD-2026-000010"
case_id = "DS-2026-000010"

ev = ev_mgr.get_evidence(ev_id)
assert ev is not None, f"Evidence {ev_id} not found"

vault_path = Path(ev.stored_path)
initial_size = vault_path.stat().st_size
hasher = hashlib.sha256()
with open(vault_path, "rb") as f:
    hasher.update(f.read())
initial_sha = hasher.hexdigest()

print(f"Original evidence: {ev.original_filename}")
print(f"Vault path: {vault_path}")
print(f"Size: {initial_size} bytes")
print(f"SHA256: {initial_sha}")

print("\nExecuting live reverse search via WebDiscoveryService...")
print("Calling wds.run_search(ev_id)... (this enriches 60 candidates and compares perceptual hashes, taking ~60-90s)")
session = wds.run_search(ev_id)

print(f"\n--- Search Completed ---")
print(f"Session ID: {session.session_id}")
print(f"Status: {session.status}")
print(f"Duration: {session.search_duration_seconds}s")
print(f"Submission Status: {session.image_submission_status}")
print(f"Total Candidate Webpages: {session.total_results}")
print(f"Total Candidate Images: {session.candidate_images_count}")
print(f"Distinct Platforms: {session.distinct_platforms}")
print(f"Platform Counts: {json.dumps(session.platform_counts, indent=2)}")
print(f"Exact Matches: {session.exact_matches}")
print(f"High Similarity: {session.high_similarity_matches}")
print(f"Partial Similarity: {session.partial_matches}")
print(f"Unverified: {session.unverified_results}")
print(f"Failed Sources: {session.failed_sources}")

# Verify immutability
after_size = vault_path.stat().st_size
hasher_after = hashlib.sha256()
with open(vault_path, "rb") as f:
    hasher_after.update(f.read())
after_sha = hasher_after.hexdigest()

print(f"\nImmutability check:")
print(f"Size unchanged: {initial_size == after_size} ({after_size} bytes)")
print(f"SHA-256 unchanged: {initial_sha == after_sha}")

# Generate fresh reports
print(f"\nGenerating fresh reports for case {case_id}...")
report = rep_svc.generate_report(case_id)
print(f"Report ID: {report.report_id}")
print(f"Formats generated: {report.formats_generated}")
for fmt, path in report.file_paths.items():
    print(f"  {fmt.upper()}: {path} (exists: {Path(path).exists()})")
