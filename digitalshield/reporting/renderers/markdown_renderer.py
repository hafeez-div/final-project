"""
Markdown renderer for DigitalShield Forensic Reports.

Generates clean, standardized GitHub-Flavored Markdown reports from ReportData.
"""

from digitalshield.reporting.models import ReportData


class MarkdownRenderer:
    """Renders ReportData into GitHub-Flavored Markdown."""

    @staticmethod
    def render(report: ReportData) -> str:
        meta = report.metadata
        case = report.case_info
        lines = []

        # --- Header ---
        lines.append("# DigitalShield Forensic Analysis Report")
        lines.append("")
        lines.append(f"**Report ID:** {meta.report_id}  ")
        lines.append(f"**Case ID:** {meta.case_id}  ")
        lines.append(f"**Case Name:** {meta.case_name}  ")
        lines.append(f"**Lead Investigator:** {meta.investigator or 'Unassigned'}  ")
        lines.append(f"**Report Generation Timestamp:** {meta.report_timestamp}  ")
        lines.append(f"**Report Specification Version:** {meta.report_version}  ")
        lines.append(f"**Forensic Suite Version:** {meta.tool_name} v{meta.software_version}  ")
        lines.append("")
        lines.append("---")
        lines.append("")

        # --- Case Overview ---
        lines.append("## 1. Case Overview & Scope")
        lines.append("")
        lines.append("| Attribute | Details |")
        lines.append("| :--- | :--- |")
        lines.append(f"| **Case ID** | {case.case_id} |")
        lines.append(f"| **Case Name** | {case.name} |")
        lines.append(f"| **Investigator** | {case.investigator or 'Unassigned'} |")
        lines.append(f"| **Status** | {case.status} |")
        lines.append(f"| **Case Initialized** | {case.created_at} |")
        lines.append(f"| **Report Generated** | {meta.report_timestamp} |")
        lines.append(f"| **Evidence Items** | {len(report.evidence_items)} item(s) ingested |")
        lines.append(f"| **Case Description** | {case.description or 'None recorded.'} |")
        lines.append("")
        lines.append("> **Forensic Timestamp Distinction:**  ")
        lines.append(f"> • **Case Creation Time:** {case.created_at}  ")
        lines.append(f"> • **Report Generation Time:** {meta.report_timestamp}  ")
        lines.append("> • *Individual evidence ingestion and public-source observation timestamps are recorded in their respective sections below.*")
        lines.append("")
        lines.append("---")
        lines.append("")

        # --- Reported Public Source URL ---
        lines.append("## Reported Public Source URL")
        lines.append("")
        if report.reported_source_url:
            lines.append(f"Reported Public Source URL:  \n`{report.reported_source_url}`")
            lines.append("")
            lines.append("Source information: URL supplied by the investigator.")
            lines.append("")
            lines.append(f"Verification status: {report.reported_source_url_status or 'Not independently verified.'}")
            lines.append("")
            lines.append(f"Recorded Timestamp (UTC): `{report.reported_source_url_recorded_at or 'Not recorded'}`  ")
            lines.append(f"Associated Case ID: `{meta.case_id}`  ")
            if report.reported_source_url_evidence_id:
                lines.append(f"Associated Evidence ID: `{report.reported_source_url_evidence_id}`  ")
            lines.append("")
            lines.append("> [!NOTE]")
            lines.append("> **Source Clarification:** This public source URL was supplied by the investigator as the location where the suspected media was observed. DigitalShield records this observation as an investigative lead; it does not claim to search the entire internet, nor does recording this URL prove that the image at this location is identical to the preserved evidence or prove who uploaded or created the content.")
        else:
            lines.append("No public source URL was provided by the investigator.")
        lines.append("")
        lines.append("---")
        lines.append("")

        # --- Evidence Inventory ---
        lines.append("## 2. Evidence Inventory & Cryptographic Baseline")
        lines.append("")
        lines.append("The following digital evidence items were ingested into the secure read-only evidence vault. Cryptographic SHA-256 hash digests represent the preserved baseline copies.")
        lines.append("")
        if not report.evidence_items:
            lines.append("*No evidence items registered in this case.*")
            lines.append("")
        else:
            lines.append("| Evidence ID | Original Filename | Format / MIME | File Size | Ingestion Timestamp (UTC) | Preserved SHA-256 Digest | Status |")
            lines.append("| :--- | :--- | :--- | :---: | :--- | :--- | :--- |")
            for ev in report.evidence_items:
                lines.append(
                    f"| `{ev.evidence_id}` | `{ev.original_filename}` | {ev.mime_type} | {ev.file_size:,} bytes | "
                    f"`{ev.import_timestamp}` | `{ev.sha256}` | {ev.status} |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")

        # --- Metadata & EXIF Findings ---
        lines.append("## 3. Technical & EXIF Metadata Findings")
        lines.append("")
        if not report.metadata_findings:
            lines.append("*No metadata extraction records found for registered evidence.*")
            lines.append("")
        else:
            for ev_id, m in report.metadata_findings.items():
                lines.append(f"### Evidence `{ev_id}` Metadata")
                if not m:
                    lines.append("*Metadata extraction was not performed or not available for this item.*")
                    lines.append("")
                    continue
                
                exif_status = "Metadata present" if m.get("exif_present") else "Metadata unavailable / Not recorded"
                lines.append(f"**EXIF Status:** {exif_status}  ")
                lines.append("")
                lines.append("| Metadata Category | Attribute | Extracted Value |")
                lines.append("| :--- | :--- | :--- |")
                lines.append(f"| **Technical** | File Format | {m.get('file_format') or 'Unknown'} |")
                lines.append(f"| **Technical** | Dimensions | {m.get('width_px')} x {m.get('height_px')} px |")
                lines.append(f"| **Technical** | Color Mode | {m.get('color_mode') or 'Unknown'} |")
                lines.append(f"| **Device EXIF** | Camera Make | {m.get('camera_make') or 'Not recorded'} |")
                lines.append(f"| **Device EXIF** | Camera Model | {m.get('camera_model') or 'Not recorded'} |")
                lines.append(f"| **Device EXIF** | Software / Firmware | {m.get('software') or 'Not recorded'} |")
                lines.append(f"| **Device EXIF** | Original Capture Timestamp | {m.get('datetime_original') or 'Not recorded in EXIF'} |")
                lines.append(f"| **Capture Settings** | Exposure Time | {m.get('exposure_time') or 'Not recorded'} |")
                lines.append(f"| **Capture Settings** | F-Number | {m.get('f_number') or 'Not recorded'} |")
                lines.append(f"| **Capture Settings** | ISO Speed Ratings | {m.get('iso_speed') or 'Not recorded'} |")
                lines.append(f"| **Capture Settings** | Focal Length | {m.get('focal_length') or 'Not recorded'} |")
                lines.append("")
                lines.append("> **Note on Absent EXIF:** The absence of EXIF metadata is standard across major messaging platforms, web browsers, and social networks that strip metadata during upload. The lack of metadata does not indicate malicious manipulation.")
                lines.append("")

        lines.append("---")
        lines.append("")

        # --- Perceptual Hashes ---
        lines.append("## 4. Perceptual Hashing & Media Fingerprints")
        lines.append("")
        lines.append("Perceptual hashes provide a normalized mathematical fingerprint of visual content structure to identify duplicate, resized, or compressed copies. Perceptual similarity measures structural similarity and does not establish original authorship or identity.")
        lines.append("")
        if not report.fingerprint_findings:
            lines.append("*No perceptual fingerprint baselines calculated for registered evidence.*")
            lines.append("")
        else:
            lines.append("| Evidence ID | Average Hash (aHash) | Difference Hash (dHash) | Perceptual Hash (pHash) | Generated (UTC) |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for ev_id, fp in report.fingerprint_findings.items():
                if not fp:
                    continue
                lines.append(
                    f"| `{ev_id}` | `{fp.get('ahash')}` | `{fp.get('dhash')}` | `{fp.get('phash')}` | `{fp.get('generation_timestamp')}` |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")

        # --- Error Level Analysis (ELA) ---
        lines.append("## 5. Error Level Analysis (ELA) Findings")
        lines.append("")
        lines.append("Error Level Analysis (ELA) examines compression rate variance across an image by comparing against a uniform JPEG recompression baseline. Unusually high error regions may highlight potential local edits or composite anomalies.")
        lines.append("")
        if not report.ela_findings:
            lines.append("*No Error Level Analysis (ELA) records found for registered evidence.*")
            lines.append("")
        else:
            for ev_id, ela in report.ela_findings.items():
                lines.append(f"### Evidence `{ev_id}` ELA Report")
                if not ela:
                    lines.append("*ELA analysis was not performed for this item.*")
                    lines.append("")
                    continue

                stats = ela.get("statistics", {})
                lines.append("| Metric | Value | Interpretation |")
                lines.append("| :--- | :---: | :--- |")
                lines.append(f"| **JPEG Quality Level** | {ela.get('recompression_quality', 90)} | Recompression baseline |")
                lines.append(f"| **Mean Error** | {ela.get('mean_error', 0.0):.4f} | Global artifact intensity |")
                lines.append(f"| **Maximum Error** | {ela.get('max_error', 0.0):.4f} | Peak local error level |")
                lines.append(f"| **Standard Deviation** | {stats.get('stddev_error', 0.0):.4f} | Error distribution variance |")
                lines.append(f"| **High Error Pixels** | {stats.get('high_error_pixels', 0):,} ({stats.get('high_error_ratio', 0.0)*100:.2f}%) | Pixels exceeding anomaly threshold |")
                lines.append(f"| **Anomaly Indicator Score** | {ela.get('anomaly_score', 0.0):.4f} | Normalized scale (0.0 = uniform, 1.0 = high variance) |")
                lines.append(f"| **Confidence** | {ela.get('confidence', 0.0)*100:.1f}% | Signal quality confidence |")
                lines.append("")
                lines.append(f"**Assessment:** {ela.get('assessment') or 'No assessment recorded.'}  ")
                lines.append(f"> **Limitations:** {ela.get('disclaimer') or 'Probabilistic indicator; not definitive proof.'}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # --- Deepfake & Synthetic Media Assessment ---
        lines.append("## 6. AI-Assisted Assessment — Deepfake & Synthetic Media")
        lines.append("")
        lines.append("> [!WARNING]")
        lines.append("> **Forensic Caution:** AI-assisted findings are probabilistic indicators and should not be treated as definitive proof of manipulation, identity, authorship, ownership, or criminal responsibility.")
        lines.append("")
        if not report.deepfake_findings:
            lines.append("*No AI-assisted deepfake assessments recorded for registered evidence.*")
            lines.append("")
        else:
            for ev_id, df in report.deepfake_findings.items():
                lines.append(f"### Evidence `{ev_id}` Synthetic Media Assessment")
                if not df:
                    lines.append("*Deepfake assessment was not performed for this item.*")
                    lines.append("")
                    continue

                prob = df.get("synthetic_probability", 0.0)
                conf = df.get("confidence", 0.0)
                lines.append("| Assessment Property | Value |")
                lines.append("| :--- | :--- |")
                lines.append(f"| **Detector Name** | {df.get('detector_name') or 'DigitalShield Baseline Detector'} |")
                lines.append(f"| **Detector Type** | {df.get('detector_type') or 'heuristic baseline'} |")
                lines.append(f"| **Synthetic Probability** | **{prob:.2f}** (0.00 to 1.00) |")
                lines.append(f"| **Assessment Confidence** | **{conf*100:.1f}%** |")
                lines.append(f"| **Status** | {df.get('status') or 'COMPLETED'} |")
                lines.append("")
                lines.append(f"**Assessment Summary:**\n{df.get('assessment') or 'No assessment statement recorded.'}")
                lines.append("")
                
                indicators = df.get("indicators", [])
                lines.append("**Observed Technical Indicators:**")
                if indicators:
                    for ind in indicators:
                        lines.append(f"- {ind}")
                else:
                    lines.append("- No specific anomalies flagged.")
                lines.append("")

                features = df.get("features_used", [])
                if features:
                    lines.append(f"**Features Evaluated:** {', '.join(features)}  ")

                limitations = df.get("limitations", [])
                if limitations:
                    lines.append("**Model Limitations & Operational Caveats:**")
                    for lim in limitations:
                        lines.append(f"> • {lim}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # --- Public URL Provenance Observations ---
        lines.append("## 7. Public URL Provenance & Investigative Leads")
        lines.append("")
        lines.append("Public URL observations record publicly accessible HTTP/HTTPS sources without authentication or platform restriction bypass. Observations use neutral terminology (*Reported source*, *Observed account*, *Publicly observed source*, *Investigative lead*, *Evidence-supported association*).")
        lines.append("")
        if not report.provenance_records:
            lines.append("*No public URL provenance records registered for this case.*")
            lines.append("")
        else:
            for rec in report.provenance_records:
                sim_str = f"{rec.get('similarity_score', 0.0)*100:.1f}%" if rec.get("similarity_score") is not None else "N/A (No media comparison)"
                lines.append(f"### Provenance Record `{rec.get('provenance_id')}` (Evidence `{rec.get('evidence_id')}`)")
                lines.append("| Provenance Attribute | Value |")
                lines.append("| :--- | :--- |")
                lines.append(f"| **Reported Source URL** | `{rec.get('source_url')}` |")
                lines.append(f"| **Source Domain** | {rec.get('source_domain') or 'Not recorded'} |")
                lines.append(f"| **Public Page Title** | {rec.get('source_title') or 'Not available'} |")
                lines.append(f"| **Observed Account / Handle** | {rec.get('observed_account_name') or 'Unknown / Not available'} |")
                lines.append(f"| **Public Media URL** | {rec.get('media_url') or 'Not available'} |")
                lines.append(f"| **Perceptual Visual Similarity** | {sim_str} |")
                lines.append(f"| **Matching Method** | {rec.get('matching_method') or 'None'} |")
                lines.append(f"| **Public Source Access Status** | {rec.get('source_status') or 'ACCESSIBLE'} |")
                lines.append(f"| **Discovery Timestamp (UTC)** | `{rec.get('discovery_timestamp') or 'Not recorded'}` |")
                lines.append(f"| **Explicit Visible Source Timestamp** | {rec.get('source_timestamp') or 'Not available from public page'} |")
                lines.append(f"| **Investigator Notes** | {rec.get('notes') or 'None recorded.'} |")
                lines.append("")
                lines.append(f"**Provenance Assessment:** {rec.get('assessment') or 'Publicly observed source recorded.'}  ")
                
                lims = rec.get("limitations", [])
                if lims:
                    lines.append("**Provenance Constraints & Disclaimers:**")
                    for lim in lims:
                        lines.append(f"> • {lim}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # --- Origin & Propagation Timeline ---
        lines.append("## 8. Origin & Propagation Timeline")
        lines.append("")
        lines.append("Chronological synthesis of evidence ingestion, public-source discovery observations, and explicit visible source page claims. Discovery timestamps are never conflated with publication timestamps.")
        lines.append("")
        if not report.timelines:
            lines.append("*No timeline events recorded for registered evidence.*")
            lines.append("")
        else:
            for ev_id, tl in report.timelines.items():
                lines.append(f"### Timeline for Evidence `{ev_id}` ({tl.get('original_filename') or 'Unknown'})")
                events = tl.get("timeline", [])
                if not events:
                    lines.append("*No chronological events recorded for this evidence item.*")
                    lines.append("")
                    continue

                lines.append("| Event Type | Timestamp (UTC) | Source / Location | Description / Details |")
                lines.append("| :--- | :--- | :--- | :--- |")
                for ev in events:
                    lines.append(
                        f"| `{ev.get('event_type')}` | `{ev.get('timestamp')}` | {ev.get('source')} | {ev.get('description')} |"
                    )
                lines.append("")

        lines.append("---")
        lines.append("")

        # --- Audit Trail Summary ---
        lines.append("## 9. Cryptographic Audit Trail & Chain of Custody")
        lines.append("")
        lines.append("Chronological chain of custody and forensic operations recorded in the local append-only SHA-256 audit log.")
        lines.append("")
        if not report.audit_events:
            lines.append("*No case-specific audit events recorded in audit log.*")
            lines.append("")
        else:
            lines.append("| Sequence / UTC Timestamp | Action Performed | Actor | Summary Target | Entry Hash (SHA-256) |")
            lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for a in report.audit_events[-20:]:  # Display up to 20 most recent relevant events
                details = a.get("details", {})
                target = details.get("evidence_id") or details.get("provenance_id") or details.get("case_id") or "Case"
                h_str = f"`{a.get('entry_hash', '')[:16]}...`" if a.get("entry_hash") else "N/A"
                lines.append(
                    f"| `{a.get('timestamp')}` | `{a.get('action')}` | {a.get('actor') or 'System'} | `{target}` | {h_str} |"
                )
            lines.append("")

        lines.append("---")
        lines.append("")


        lines.append("---")
        lines.append("")

        # --- Public Online Image Discovery and Reverse Image Search Findings ---
        lines.append("## 10. Public Reverse Image Search Findings – Google Lens")
        lines.append("### Public Online Image Discovery and Reverse Image Search Findings")
        lines.append("")
        lines.append(
            "Reverse image search results depend on the external provider's indexed and accessible content. "
            "Google Lens does not provide an official standalone public developer API; automated discovery "
            "operates via compliant search gateways. DigitalShield cannot guarantee discovery of every online "
            "occurrence. A missing result does not establish that an image has never been published online. "
            "Perceptual hash similarity is an investigative indicator and does not independently establish image "
            "identity, unauthorized distribution, or the identity of an uploader."
        )
        lines.append("")

        sessions = getattr(report, "web_discovery_sessions", []) or []
        wd_results = getattr(report, "web_discovery_results", []) or []

        if not sessions:
            lines.append("*No reverse image search or public web discovery sessions have been executed for this case.*")
            lines.append("")
        else:
            for sess in sessions:
                sid = sess.get("session_id") or sess.get("discovery_id", "N/A")
                ev_id = sess.get("evidence_id", "N/A")
                provider = sess.get("provider", "Google Lens")
                status = sess.get("status", "N/A")
                sub_status = sess.get("image_submission_status", "SUBMITTED")
                dur = sess.get("search_duration_seconds")
                dur_str = f"{dur:.3f}s" if dur is not None else "N/A"
                started = sess.get("started_at") or sess.get("search_timestamp", "N/A")
                completed = sess.get("completed_at") or "N/A"
                total_webpages = sess.get("total_results", 0) or sess.get("total_candidates", 0)
                total_images = sess.get("candidate_images_count", 0)
                exact_matches = sess.get("exact_matches", 0)
                high_matches = sess.get("high_similarity_matches", 0)
                partial_matches = sess.get("partial_matches", 0)
                verified = sess.get("verified_matches", 0)
                unverified = sess.get("unverified_results", 0)
                failed = sess.get("failed_sources", 0)
                pcounts: dict = sess.get("platform_counts") or {}
                distinct = sess.get("distinct_platforms", len(pcounts))

                lines.append(f"## Session {sid} — Evidence {ev_id}")
                lines.append("")
                lines.append("| Metric | Details |")
                lines.append("| :--- | :--- |")
                lines.append(f"| **Case ID** | {case.case_id} |")
                lines.append(f"| **Evidence ID** | {ev_id} |")
                lines.append(f"| **Search Provider** | {provider} |")
                lines.append(f"| **Search Status** | {status} |")
                lines.append(f"| **Search Duration** | {dur_str} |")
                lines.append(f"| **Image Submission Status** | `{sub_status}` |")
                lines.append(f"| **Initiation Timestamp (UTC)** | {started} |")
                lines.append(f"| **Completion Timestamp (UTC)** | {completed} |")
                lines.append(f"| **Total Candidate Webpages Discovered** | {total_webpages} |")
                lines.append(f"| **Total Candidate Images** | {total_images} |")
                lines.append(f"| **Distinct Platforms Identified** | {distinct} |")
                lines.append(f"| **Exact or Near-Exact Visual Matches** | {exact_matches} |")
                lines.append(f"| **High Visual Similarity Matches** | {high_matches} |")
                lines.append(f"| **Partial Visual Similarity Matches** | {partial_matches} |")
                lines.append(f"| **Unverified Candidates** | {unverified} |")
                lines.append(f"| **Failed Web Sources** | {failed} |")
                if sess.get("error_message"):
                    lines.append(f"| **Status / Error Message** | {sess['error_message']} |")
                lines.append("")

                sess_results = [
                    r for r in wd_results
                    if r.get("session_id") == sid or r.get("discovery_id") == sid
                ]

                if not sess_results:
                    if status == "NO_RESULTS":
                        lines.append("*No matching public sources were discovered during the search.*")
                    elif status in ("PROVIDER_UNAVAILABLE", "MISSING_CREDENTIALS"):
                        lines.append(
                            "> [!WARNING]\n"
                            "> **Reverse Image Search Gateway Not Configured:** Google Lens does not provide an official "
                            "unauthenticated public API. DigitalShield requires a configured gateway (SERPAPI_API_KEY, "
                            "GOOGLE_LENS_API_KEY, or SEARCHAPI_API_KEY) in the environment or .env file to enable automated online discovery."
                        )
                    elif status == "BLOCKED":
                        lines.append(
                            "> [!WARNING]\n"
                            "> **Reverse Image Search Blocked:** The external search gateway blocked the request or hit rate limits (HTTP 429)."
                        )
                    elif status in ("FAILED", "PARSE_ERROR"):
                        lines.append(f"*Reverse search failed or provider unavailable: {sess.get('error_message', 'Provider error')}.*")
                    else:
                        lines.append("*No matching public sources were discovered during the search.*")
                    lines.append("")
                else:
                    # ── Platform Summary Table ──────────────────────────────────────
                    if pcounts:
                        lines.append("### Platform Summary")
                        lines.append("")
                        lines.append("| Platform | Results | Accessible | Inaccessible |")
                        lines.append("| :--- | :---: | :---: | :---: |")
                        for pname, pcount in sorted(pcounts.items(), key=lambda x: -x[1]):
                            accessible = sum(
                                1 for r in sess_results
                                if (r.get("platform") or r.get("domain")) == pname
                                and r.get("scrape_status") == "SUCCESS"
                            )
                            inaccessible = pcount - accessible
                            lines.append(f"| {pname} | {pcount} | {accessible} | {inaccessible} |")
                        lines.append("")

                    # ── Social Media & Public Website Source Findings ───────────────
                    lines.append("### Social Media and Public Website Source Findings")
                    lines.append("")
                    lines.append(
                        "> [!NOTE]\n"
                        "> Results below are grouped by platform. A platform name identifies the hosting website, "
                        "not the identity of the person who uploaded the content. "
                        "Google Thumbnail Cache entries (encrypted-tbn*.gstatic.com) are CDN-cached previews "
                        "and are NOT the original publishing webpage."
                    )
                    lines.append("")

                    # Group results by platform
                    from collections import defaultdict as _dd
                    grouped: dict = _dd(list)
                    for r in sess_results:
                        pname = r.get("platform") or r.get("domain") or "Web Source"
                        grouped[pname].append(r)

                    # Define rendering order: social first, then alphabetical
                    _priority = [
                        "X (Twitter)", "Reddit", "Instagram", "Facebook",
                        "YouTube", "TikTok", "Pinterest", "LinkedIn", "Wikipedia",
                        "Wikimedia", "Fandom Wiki", "Tumblr", "Flickr",
                    ]
                    ordered_platforms = [p for p in _priority if p in grouped]
                    ordered_platforms += sorted(p for p in grouped if p not in _priority)

                    for pname in ordered_platforms:
                        p_results = grouped[pname]
                        lines.append(f"#### {pname} ({len(p_results)} result{'s' if len(p_results) != 1 else ''})")
                        lines.append("")
                        lines.append("| Field | Value |")
                        lines.append("| :--- | :--- |")

                        for r in p_results:
                            rid      = r.get("result_id", "N/A")
                            src_url  = r.get("source_url", "N/A")
                            title    = r.get("page_title") or r.get("og_title") or "Not available"
                            src_type = r.get("source_type") or "Public Website"
                            is_gthumbnail = r.get("is_google_thumbnail", False)
                            med_url  = r.get("media_url") or r.get("og_image") or "Not available"
                            calc_val = r.get("calculated_similarity") or r.get("independent_similarity_score")
                            sim_str  = f"{calc_val:.4f} ({calc_val*100:.1f}%)" if calc_val is not None else "Not calculated"
                            vstatus  = r.get("verification_status", "Awaiting investigator review")
                            sstatus  = r.get("scrape_status", "N/A")
                            author   = r.get("author") or "Not publicly visible"
                            pub_ts   = r.get("publication_timestamp") or "Not available"
                            disc_ts  = r.get("discovery_timestamp") or r.get("retrieval_timestamp", "N/A")
                            mtype    = r.get("provider_match_type", "N/A")
                            method_str = r.get("independent_matching_method") or "pHash+aHash+dHash (independently calculated by DigitalShield)"
                            ahash_d  = r.get("ahash_distance", "N/A")
                            dhash_d  = r.get("dhash_distance", "N/A")
                            phash_d  = r.get("phash_distance", "N/A")

                            thumbnail_warning = ""
                            if is_gthumbnail:
                                thumbnail_warning = " ⚠ Google Thumbnail Cache — not the original publishing webpage"

                            lines.append(f"| **Result ID** | `{rid}` |")
                            lines.append(f"| **Platform** | {pname}{thumbnail_warning} |")
                            lines.append(f"| **Source Type** | {src_type} |")
                            lines.append(f"| **Page Title** | {title} |")
                            if src_url != "N/A":
                                lines.append(f"| **Original Webpage URL** | [{src_url}]({src_url}) |")
                            else:
                                lines.append("| **Original Webpage URL** | Original source webpage not identified |")
                            if med_url != "Not available":
                                lines.append(f"| **Discovered Image URL** | [{med_url}]({med_url}) |")
                            else:
                                lines.append("| **Discovered Image URL** | Not available |")
                            lines.append(f"| **Author / Account** | {author} |")
                            lines.append(f"| **Publication Date** | {pub_ts} |")
                            lines.append(f"| **Discovery Timestamp (UTC)** | {disc_ts} |")
                            lines.append(f"| **Provider Match Type** | {mtype} |")
                            lines.append(f"| **Perceptual Similarity** | {sim_str} ({method_str}) |")
                            lines.append(f"| **Hamming Distances** | aHash: {ahash_d}, dHash: {dhash_d}, pHash: {phash_d} |")
                            lines.append(f"| **Verification Status** | {vstatus} |")
                            lines.append(f"| **Page Accessibility** | {sstatus} |")
                            lines.append("")

        lines.append(
            "> ⚠ **Limitation Statement:** Reverse image search results depend on the external provider's indexed "
            "and accessible content. DigitalShield cannot guarantee discovery of every online occurrence. A missing result "
            "does not establish that an image has never been published online. Perceptual hash similarity is an "
            "investigative indicator and does not independently establish image identity, unauthorized distribution, "
            "or the identity of an uploader."
        )
        lines.append("")

        # --- Objective Findings Summary ---
        lines.append("## 11. Summary of Objective Technical Findings")
        lines.append("")
        if report.overall_findings:
            for item in report.overall_findings:
                lines.append(f"- {item}")
        else:
            lines.append("- Digital evidence was successfully imported and verified against cryptographic SHA-256 baselines.")
            lines.append("- Read-only forensic integrity maintained across all analysis modules.")
        lines.append("")

        lines.append("---")
        lines.append("")

        # --- Forensic Limitations ---
        lines.append("## 12. Forensic & Legal Limitations")
        lines.append("")
        if report.limitations:
            for lim in report.limitations:
                lines.append(f"1. {lim}")
        else:
            lines.append("1. All analysis results are derived forensic indicators and must be evaluated alongside independent corroborating evidence.")
            lines.append("2. DigitalShield does not determine legal guilt, civil liability, or criminal culpability.")
        lines.append("")

        lines.append("---")
        lines.append("")

        # --- Investigator Notes ---
        lines.append("## 13. Investigator / Case Notes")
        lines.append("")
        if report.investigator_notes:
            lines.append(report.investigator_notes)
        else:
            lines.append("*None recorded.*")
            lines.append("")

        lines.append("")
        lines.append("---")
        lines.append(f"*Report generated locally by DigitalShield Forensic Suite v{meta.software_version}. Zero external network requests made.*")

        return "\n".join(lines)
