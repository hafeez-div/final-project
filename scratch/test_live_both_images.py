import os
import sys
import json
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
from digitalshield.reporting.service import ReportingService

base_dir = Path(".digitalshield_data")
ev_mgr = EvidenceManager(base_dir=base_dir)
wds = WebDiscoveryService(base_dir=base_dir)
rep_svc = ReportingService(base_dir=base_dir)

def test_evidence(case_id, ev_id, label):
    print(f"\n==================================================")
    print(f"TESTING EVIDENCE: {label} ({ev_id} in {case_id})")
    print(f"==================================================")

    ev = ev_mgr.get_evidence(ev_id)
    if not ev:
        print(f"Error: Evidence {ev_id} not found!")
        return

    print(f"Original filename: {ev.original_filename}")
    print(f"Vault path: {ev.stored_path}")
    print(f"SHA-256: {ev.sha256[:20]}...")

    print(f"\nExecuting WebDiscoveryService.run_search('{ev_id}')...")
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

    results = wds.list_results_by_session(session.session_id)
    print(f"\nStored WebDiscoveryResults count: {len(results)}")

    # Check platforms discovered
    platforms = set(r.platform for r in results)
    print(f"Unique platforms found: {sorted(platforms)}")

    # Sample results per recognized platform
    print("\nSample Results per Platform:")
    shown = set()
    for r in results:
        p = r.platform or "Unknown"
        if p not in shown and len(shown) < 10:
            shown.add(p)
            print(f"  [{p}] (Source Type: {r.source_type})")
            print(f"    Title: {r.page_title}")
            print(f"    Webpage URL: {r.source_url}")
            print(f"    Image URL: {r.media_url}")
            print(f"    Is Google Thumbnail: {r.is_google_thumbnail}")
            print(f"    Scrape Status: {r.scrape_status} | Sim: {r.calculated_similarity} | Verif: {r.verification_status}")

    # Generate reports
    print(f"\nGenerating reports for {case_id}...")
    rec, files = rep_svc.generate_report(case_id, formats=["markdown", "html", "pdf"])
    for fmt, p in files.items():
        print(f"  {fmt.upper()} Report: {p} (Size: {Path(p).stat().st_size} bytes)")

    return session, results

print("Starting live test on both images...")
# Generate report for Michael Jackson using the freshly completed session WDS-2026-000014
print("\n--- Generating Reports for Michael Jackson (DS-2026-000001) ---")
rec_mj, files_mj = rep_svc.generate_report("DS-2026-000001", formats=["markdown", "html", "pdf"])
for fmt, p in files_mj.items():
    print(f"  {fmt.upper()} Report: {p} (Size: {Path(p).stat().st_size} bytes)")

# Now test Mr. Bean
res_bean = test_evidence("DS-2026-000003", "EVD-2026-000003", "Mr. Bean (beeen.jpeg)")
print("\nALL TESTS COMPLETE!")
