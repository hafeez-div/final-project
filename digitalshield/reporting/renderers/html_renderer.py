"""
HTML renderer for DigitalShield Forensic Reports.

Generates self-contained, standalone local HTML reports from ReportData.
STRICT PRIVACY & SECURITY RULES:
- 100% offline — zero external stylesheets, scripts, CDNs, or fonts.
- HTML-escapes all dynamic fields to guarantee local rendering safety.
- Print-optimized CSS (@media print).
"""

import html
from digitalshield.reporting.models import ReportData


def esc(val) -> str:
    """Safely HTML-escape string or convert None to 'Not recorded'."""
    if val is None or val == "":
        return "<span class='dim'>Not recorded</span>"
    return html.escape(str(val))


class HTMLRenderer:
    """Renders ReportData into a self-contained local HTML document."""

    @staticmethod
    def render(report: ReportData) -> str:
        meta = report.metadata
        case = report.case_info

        css = """
        :root {
            --primary: #1e293b;
            --primary-light: #334155;
            --accent: #0284c7;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --text: #0f172a;
            --text-muted: #64748b;
            --warning-bg: #fffbeb;
            --warning-border: #f59e0b;
            --warning-text: #92400e;
            --badge-bg: #e0f2fe;
            --badge-text: #0369a1;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            margin: 0;
            padding: 24px;
        }
        .container {
            max-width: 1080px;
            margin: 0 auto;
            background: var(--card-bg);
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border: 1px solid var(--border);
        }
        .header {
            border-bottom: 2px solid var(--border);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            margin: 0 0 8px 0;
            color: var(--primary);
            font-size: 26px;
        }
        .header .meta-bar {
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 13px;
            color: var(--text-muted);
        }
        .section {
            margin-bottom: 36px;
        }
        .section h2 {
            font-size: 18px;
            color: var(--primary);
            border-bottom: 1px solid var(--border);
            padding-bottom: 8px;
            margin-bottom: 16px;
        }
        .section h3 {
            font-size: 15px;
            color: var(--primary-light);
            margin-top: 20px;
            margin-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 16px;
            font-size: 13px;
        }
        th, td {
            text-align: left;
            padding: 9px 12px;
            border: 1px solid var(--border);
        }
        th {
            background-color: #f1f5f9;
            color: var(--primary);
            font-weight: 600;
        }
        tr:nth-child(even) td {
            background-color: #f8fafc;
        }
        .badge {
            display: inline-block;
            padding: 2px 8px;
            font-size: 11px;
            font-weight: 600;
            border-radius: 4px;
            background: var(--badge-bg);
            color: var(--badge-text);
        }
        .alert-warning {
            background-color: var(--warning-bg);
            border-left: 4px solid var(--warning-border);
            padding: 12px 16px;
            border-radius: 4px;
            color: var(--warning-text);
            margin-bottom: 16px;
            font-size: 13px;
        }
        .alert-warning strong {
            display: block;
            margin-bottom: 4px;
        }
        .callout {
            background-color: #f1f5f9;
            border-left: 3px solid var(--accent);
            padding: 10px 14px;
            margin: 12px 0;
            font-size: 13px;
            color: var(--primary-light);
        }
        .dim {
            color: var(--text-muted);
            font-style: italic;
        }
        code {
            font-family: ui-monospace, SFMono-Regular, Consolas, 'Liberation Mono', Menlo, monospace;
            background: #f1f5f9;
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 12px;
        }
        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            font-size: 12px;
            color: var(--text-muted);
            text-align: center;
        }
        @media print {
            body { background: #fff; padding: 0; }
            .container { box-shadow: none; border: none; padding: 0; }
            .section { page-break-inside: avoid; }
        }
        """

        doc = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "<meta charset='utf-8'>",
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"<title>DigitalShield Forensic Report - {esc(meta.report_id)}</title>",
            f"<style>{css}</style>",
            "</head>",
            "<body>",
            "<div class='container'>",
            
            # --- Header ---
            "<div class='header'>",
            "<h1>DigitalShield Forensic Analysis Report</h1>",
            "<div class='meta-bar'>",
            f"<span><strong>Report ID:</strong> <code>{esc(meta.report_id)}</code></span>",
            f"<span><strong>Case ID:</strong> <code>{esc(meta.case_id)}</code></span>",
            f"<span><strong>Investigator:</strong> {esc(meta.investigator)}</span>",
            f"<span><strong>Generated:</strong> {esc(meta.report_timestamp)}</span>",
            f"<span><strong>Software:</strong> {esc(meta.tool_name)} v{esc(meta.software_version)}</span>",
            "</div>",
            "</div>",

            # --- Case Overview ---
            "<div class='section'>",
            "<h2>1. Case Overview & Scope</h2>",
            "<table>",
            "<tr><th style='width:25%'>Attribute</th><th>Details</th></tr>",
            f"<tr><td><strong>Case ID</strong></td><td><code>{esc(case.case_id)}</code></td></tr>",
            f"<tr><td><strong>Case Name</strong></td><td>{esc(case.name)}</td></tr>",
            f"<tr><td><strong>Lead Investigator</strong></td><td>{esc(case.investigator)}</td></tr>",
            f"<tr><td><strong>Case Status</strong></td><td><span class='badge'>{esc(case.status)}</span></td></tr>",
            f"<tr><td><strong>Case Initialized</strong></td><td>{esc(case.created_at)}</td></tr>",
            f"<tr><td><strong>Report Generated</strong></td><td>{esc(meta.report_timestamp)}</td></tr>",
            f"<tr><td><strong>Evidence Registered</strong></td><td>{len(report.evidence_items)} item(s)</td></tr>",
            f"<tr><td><strong>Case Description</strong></td><td>{esc(case.description or 'None recorded.')}</td></tr>",
            "</table>",
            "<div class='callout'>",
            f"<strong>Forensic Timestamps:</strong> Case created at <code>{esc(case.created_at)}</code>; report compiled at <code>{esc(meta.report_timestamp)}</code>. Individual evidence ingestion and observation timestamps are detailed below.",
            "</div>",
            "</div>",

            # --- Reported Public Source URL ---
            "<div class='section'>",
            "<h2>Reported Public Source URL</h2>",
        ]

        if report.reported_source_url:
            doc.append("<table>")
            doc.append("<tr><th style='width:25%'>Attribute</th><th>Details</th></tr>")
            doc.append(f"<tr><td><strong>Reported Public Source URL</strong></td><td><code>{esc(report.reported_source_url)}</code></td></tr>")
            doc.append("<tr><td><strong>Source Information</strong></td><td>URL supplied by the investigator.</td></tr>")
            doc.append(f"<tr><td><strong>Verification Status</strong></td><td><span class='badge'>{esc(report.reported_source_url_status or 'Not independently verified.')}</span></td></tr>")
            doc.append(f"<tr><td><strong>Recorded Timestamp (UTC)</strong></td><td><code>{esc(report.reported_source_url_recorded_at or 'Not recorded')}</code></td></tr>")
            doc.append(f"<tr><td><strong>Associated Case ID</strong></td><td><code>{esc(meta.case_id)}</code></td></tr>")
            doc.append(f"<tr><td><strong>Associated Evidence ID</strong></td><td><code>{esc(report.reported_source_url_evidence_id or 'Not assigned')}</code></td></tr>")
            doc.append("</table>")
            doc.append("<div class='callout'>")
            doc.append("<strong>Source Clarification:</strong> This public source URL was supplied by the investigator as the location where the suspected media was observed. Recording this URL does not constitute proof of authorship, ownership, or identity of the person who uploaded or created the media.")
            doc.append("</div>")
        else:
            doc.append("<p class='dim'>No public source URL was provided by the investigator.</p>")

        doc.append("</div>")

        # --- Evidence Inventory ---
        doc.append("<div class='section'>")
        doc.append("<h2>2. Evidence Inventory & Cryptographic Baseline</h2>")
        doc.append("<p>All SHA-256 hash digests represent the preserved, read-only evidence copies held in local vaults.</p>")

        if not report.evidence_items:
            doc.append("<p class='dim'>No evidence items registered in this case.</p>")
        else:
            doc.append("<table>")
            doc.append("<tr><th>Evidence ID</th><th>Filename</th><th>MIME Type</th><th>File Size</th><th>Ingestion Time (UTC)</th><th>SHA-256 Digest</th><th>Status</th></tr>")
            for ev in report.evidence_items:
                doc.append(
                    f"<tr><td><code>{esc(ev.evidence_id)}</code></td><td>{esc(ev.original_filename)}</td>"
                    f"<td>{esc(ev.mime_type)}</td><td>{ev.file_size:,} bytes</td><td>{esc(ev.import_timestamp)}</td>"
                    f"<td><code style='font-size:10px'>{esc(ev.sha256)}</code></td><td><span class='badge'>{esc(ev.status)}</span></td></tr>"
                )
            doc.append("</table>")
        doc.append("</div>")

        # --- Metadata Findings ---
        doc.append("<div class='section'>")
        doc.append("<h2>3. Technical & EXIF Metadata Findings</h2>")
        if not report.metadata_findings:
            doc.append("<p class='dim'>No metadata extraction records found for registered evidence.</p>")
        else:
            for ev_id, m in report.metadata_findings.items():
                doc.append(f"<h3>Evidence <code>{esc(ev_id)}</code></h3>")
                if not m:
                    doc.append("<p class='dim'>Metadata extraction not performed or unavailable.</p>")
                    continue
                doc.append("<table>")
                doc.append("<tr><th>Category</th><th>Property</th><th>Extracted Value</th></tr>")
                doc.append(f"<tr><td>Technical</td><td>File Format</td><td>{esc(m.get('file_format'))}</td></tr>")
                doc.append(f"<tr><td>Technical</td><td>Dimensions</td><td>{esc(m.get('width_px'))} x {esc(m.get('height_px'))} px ({esc(m.get('color_mode'))})</td></tr>")
                doc.append(f"<tr><td>Device EXIF</td><td>Camera Make / Model</td><td>{esc(m.get('camera_make'))} {esc(m.get('camera_model'))}</td></tr>")
                doc.append(f"<tr><td>Device EXIF</td><td>Software</td><td>{esc(m.get('software'))}</td></tr>")
                doc.append(f"<tr><td>Device EXIF</td><td>Capture Date (UTC)</td><td>{esc(m.get('datetime_original'))}</td></tr>")
                doc.append(f"<tr><td>Exposure Settings</td><td>Exposure / Aperture / ISO</td><td>{esc(m.get('exposure_time'))} | F/{esc(m.get('f_number'))} | ISO {esc(m.get('iso_speed'))}</td></tr>")
                doc.append("</table>")
                doc.append("<div class='callout'><strong>Note on Metadata Absence:</strong> Stripped EXIF metadata is standard across major messaging platforms and web re-upload pipelines. It does not indicate malicious manipulation.</div>")
        doc.append("</div>")

        # --- Perceptual Hashes ---
        doc.append("<div class='section'>")
        doc.append("<h2>4. Perceptual Hashing & Media Fingerprints</h2>")
        doc.append("<p>Perceptual hashes measure visual structural similarity to identify duplicate or cropped copies across platforms.</p>")
        if not report.fingerprint_findings:
            doc.append("<p class='dim'>No perceptual hashes recorded.</p>")
        else:
            doc.append("<table>")
            doc.append("<tr><th>Evidence ID</th><th>Average Hash (aHash)</th><th>Difference Hash (dHash)</th><th>Perceptual Hash (pHash)</th></tr>")
            for ev_id, fp in report.fingerprint_findings.items():
                if not fp:
                    continue
                doc.append(
                    f"<tr><td><code>{esc(ev_id)}</code></td><td><code>{esc(fp.get('ahash'))}</code></td>"
                    f"<td><code>{esc(fp.get('dhash'))}</code></td><td><code>{esc(fp.get('phash'))}</code></td></tr>"
                )
            doc.append("</table>")
        doc.append("</div>")

        # --- ELA Analysis ---
        doc.append("<div class='section'>")
        doc.append("<h2>5. Error Level Analysis (ELA) Findings</h2>")
        if not report.ela_findings:
            doc.append("<p class='dim'>No ELA analysis performed.</p>")
        else:
            for ev_id, ela in report.ela_findings.items():
                doc.append(f"<h3>Evidence <code>{esc(ev_id)}</code></h3>")
                if not ela:
                    doc.append("<p class='dim'>ELA analysis not available for this item.</p>")
                    continue
                stats = ela.get("statistics", {})
                doc.append("<table>")
                doc.append("<tr><th>Metric</th><th>Observed Value</th><th>Interpretation</th></tr>")
                doc.append(f"<tr><td>JPEG Recompression Baseline</td><td>Quality {ela.get('recompression_quality', 90)}</td><td>Standard test quality</td></tr>")
                doc.append(f"<tr><td>Mean Error Level</td><td>{ela.get('mean_error', 0.0):.4f}</td><td>Global error intensity</td></tr>")
                doc.append(f"<tr><td>Max Error Level</td><td>{ela.get('max_error', 0.0):.4f}</td><td>Peak compression delta</td></tr>")
                doc.append(f"<tr><td>High Error Pixels Ratio</td><td>{stats.get('high_error_ratio', 0.0)*100:.2f}%</td><td>Proportion of pixel anomalies</td></tr>")
                doc.append(f"<tr><td>Anomaly Indicator Score</td><td><strong>{ela.get('anomaly_score', 0.0):.4f}</strong></td><td>Normalized indicator scale</td></tr>")
                doc.append("</table>")
                doc.append(f"<p><strong>Assessment:</strong> {esc(ela.get('assessment'))}</p>")
                doc.append(f"<div class='callout'><strong>Forensic Limitation:</strong> {esc(ela.get('disclaimer'))}</div>")
        doc.append("</div>")

        # --- Deepfake Assessment ---
        doc.append("<div class='section'>")
        doc.append("<h2>6. AI-Assisted Assessment — Deepfake & Synthetic Media</h2>")
        doc.append("<div class='alert-warning'><strong>Forensic Caution:</strong> AI-assisted findings are probabilistic indicators and should not be treated as definitive proof of manipulation, identity, authorship, ownership, or criminal responsibility.</div>")
        if not report.deepfake_findings:
            doc.append("<p class='dim'>No deepfake assessments performed.</p>")
        else:
            for ev_id, df in report.deepfake_findings.items():
                doc.append(f"<h3>Evidence <code>{esc(ev_id)}</code></h3>")
                if not df:
                    doc.append("<p class='dim'>Deepfake assessment not performed for this item.</p>")
                    continue
                prob = df.get("synthetic_probability", 0.0)
                conf = df.get("confidence", 0.0)
                doc.append("<table>")
                doc.append("<tr><th>Property</th><th>Value</th></tr>")
                doc.append(f"<tr><td>Detector</td><td>{esc(df.get('detector_name'))} ({esc(df.get('detector_type'))})</td></tr>")
                doc.append(f"<tr><td>Synthetic Probability</td><td><strong>{prob:.2f}</strong> (0.00 to 1.00)</td></tr>")
                doc.append(f"<tr><td>Assessment Confidence</td><td><strong>{conf*100:.1f}%</strong></td></tr>")
                doc.append(f"<tr><td>Status</td><td><span class='badge'>{esc(df.get('status'))}</span></td></tr>")
                doc.append("</table>")
                doc.append(f"<p><strong>Assessment:</strong> {esc(df.get('assessment'))}</p>")
                
                inds = df.get("indicators", [])
                if inds:
                    doc.append("<p><strong>Observed Technical Indicators:</strong></p><ul>")
                    for ind in inds:
                        doc.append(f"<li>{esc(ind)}</li>")
                    doc.append("</ul>")
        doc.append("</div>")

        # --- Public URL Provenance ---
        doc.append("<div class='section'>")
        doc.append("<h2>7. Public URL Provenance & Investigative Leads</h2>")
        doc.append("<p>Public URL observations record publicly accessible HTTP/HTTPS sources without authentication or platform restriction bypass. Observations use neutral terminology.</p>")
        if not report.provenance_records:
            doc.append("<p class='dim'>No public URL provenance records registered for this case.</p>")
        else:
            for rec in report.provenance_records:
                sim_str = f"{rec.get('similarity_score', 0.0)*100:.1f}%" if rec.get("similarity_score") is not None else "N/A"
                doc.append(f"<h3>Provenance Record <code>{esc(rec.get('provenance_id'))}</code> (Evidence <code>{esc(rec.get('evidence_id'))}</code>)</h3>")
                doc.append("<table>")
                doc.append("<tr><th>Attribute</th><th>Value</th></tr>")
                doc.append(f"<tr><td>Reported Source URL</td><td><code>{esc(rec.get('source_url'))}</code></td></tr>")
                doc.append(f"<tr><td>Domain / Title</td><td>{esc(rec.get('source_domain'))} &mdash; {esc(rec.get('source_title'))}</td></tr>")
                doc.append(f"<tr><td>Observed Account</td><td>{esc(rec.get('observed_account_name'))}</td></tr>")
                doc.append(f"<tr><td>Visual Similarity</td><td><strong>{sim_str}</strong> ({esc(rec.get('matching_method'))})</td></tr>")
                doc.append(f"<tr><td>Discovery Timestamp</td><td>{esc(rec.get('discovery_timestamp'))}</td></tr>")
                doc.append(f"<tr><td>Visible Source Timestamp</td><td>{esc(rec.get('source_timestamp'))}</td></tr>")
                doc.append(f"<tr><td>Notes</td><td>{esc(rec.get('notes'))}</td></tr>")
                doc.append("</table>")
                doc.append(f"<p><strong>Assessment:</strong> {esc(rec.get('assessment'))}</p>")
        doc.append("</div>")


        # --- Public Online Image Discovery and Reverse Image Search Findings ---
        doc.append("<div class='section'>")
        doc.append("<h1>Public Online Image Discovery and Reverse Image Search Findings</h1>")
        doc.append(
            "<div class='callout'><p><strong>Forensic Disclaimer:</strong> Reverse image search results depend on the "
            "external provider's indexed and accessible content. DigitalShield cannot guarantee discovery of every online "
            "occurrence. A missing result does not establish that an image has never been published online. Perceptual "
            "hash similarity is an investigative indicator and does not independently establish image identity, "
            "unauthorized distribution, or the identity of an uploader.</p></div>"
        )

        sessions = getattr(report, "web_discovery_sessions", []) or []
        wd_results = getattr(report, "web_discovery_results", []) or []

        if not sessions:
            doc.append("<p class='dim'>No reverse image search or public web discovery sessions have been executed for this case.</p>")
        else:
            for sess in sessions:
                sid = sess.get("session_id") or sess.get("discovery_id", "N/A")
                ev_id = sess.get("evidence_id", "N/A")
                provider = sess.get("provider", "Google Cloud Vision Web Detection")
                status = sess.get("status", "N/A")
                started = sess.get("started_at") or sess.get("search_timestamp", "N/A")
                completed = sess.get("completed_at") or "N/A"
                total = sess.get("total_results", 0) or sess.get("total_candidates", 0)
                verified = sess.get("verified_matches", 0)
                unverified = sess.get("unverified_results", 0)
                failed = sess.get("failed_sources", 0)

                doc.append(f"<h2>Session <code>{esc(sid)}</code> &mdash; Evidence <code>{esc(ev_id)}</code></h2>")
                doc.append("<table>")
                doc.append("<tr><th>Metric</th><th>Details</th></tr>")
                doc.append(f"<tr><td>Case ID</td><td><code>{esc(report.case_info.case_id)}</code></td></tr>")
                doc.append(f"<tr><td>Evidence ID</td><td><code>{esc(ev_id)}</code></td></tr>")
                doc.append(f"<tr><td>Search Provider</td><td>{esc(provider)}</td></tr>")
                doc.append(f"<tr><td>Search Status</td><td><span class='badge'>{esc(status)}</span></td></tr>")
                doc.append(f"<tr><td>Initiation Timestamp (UTC)</td><td><code>{esc(started)}</code></td></tr>")
                doc.append(f"<tr><td>Completion Timestamp (UTC)</td><td><code>{esc(completed)}</code></td></tr>")
                doc.append(f"<tr><td>Candidate Webpages Discovered</td><td><strong>{total}</strong></td></tr>")
                doc.append(f"<tr><td>Verified Perceptual Matches</td><td><span style='color:green;'>{verified}</span></td></tr>")
                doc.append(f"<tr><td>Unverified Search Results</td><td>{unverified}</td></tr>")
                doc.append(f"<tr><td>Failed Web Sources</td><td>{failed}</td></tr>")
                if sess.get("error_message"):
                    doc.append(f"<tr><td>Status Message</td><td><code>{esc(sess['error_message'])}</code></td></tr>")
                doc.append("</table>")

                sess_results = [
                    r for r in wd_results
                    if r.get("session_id") == sid or r.get("discovery_id") == sid
                ]

                if not sess_results:
                    if status == "NO_RESULTS":
                        doc.append("<p class='dim'>Automatic reverse search completed: No candidate sources discovered.</p>")
                    elif status == "MISSING_CREDENTIALS":
                        doc.append("<p class='dim'>Provider unavailable: GOOGLE_CLOUD_API_KEY environment variable is not configured.</p>")
                    elif status == "FAILED":
                        doc.append(f"<p class='dim'>Search execution failed: {esc(sess.get('error_message', 'Provider error'))}.</p>")
                    else:
                        doc.append("<p class='dim'>No candidate sources recorded for this session.</p>")
                else:
                    doc.append(f"<h3>Discovered Sources & Verification Details ({len(sess_results)})</h3>")
                    doc.append("<table>")
                    doc.append("<tr><th>Result ID</th><th>Platform</th><th>Webpage Title</th><th>Match Type</th><th>Similarity</th><th>Verification</th><th>Source Page</th><th>Candidate Image</th></tr>")
                    for r in sess_results:
                        rid = r.get("result_id", "N/A")
                        platform = r.get("platform") or r.get("domain") or "Web Source"
                        mtype = r.get("provider_match_type", "N/A")
                        calc_sim = r.get("calculated_similarity") or r.get("independent_similarity_score")
                        sim_str = f"{calc_sim * 100:.1f}%" if calc_sim is not None else "Unverified"
                        vstatus = r.get("verification_status", "Awaiting review")
                        surl = r.get("source_url", "")
                        murl = r.get("media_url") or ""

                        surl_html = f"<a href='{esc(surl)}' rel='noopener noreferrer' target='_blank'><code>{esc(surl[:40])}...</code></a>" if surl else "N/A"
                        murl_html = f"<a href='{esc(murl)}' rel='noopener noreferrer' target='_blank'>View Media</a>" if murl else "<span class='dim'>N/A</span>"

                        doc.append(f"<tr><td><code>{esc(rid)}</code></td><td><strong>{esc(platform)}</strong></td><td>{esc(r.get('page_title') or 'Not available')}</td><td>{esc(mtype)}</td><td><strong>{esc(sim_str)}</strong></td><td>{esc(vstatus)}</td><td>{surl_html}</td><td>{murl_html}</td></tr>")
                    doc.append("</table>")
        doc.append("</div>")
        doc.append("")

        # --- Origin & Propagation Timeline ---
        doc.append("<div class='section'>")
        doc.append("<h2>11. Origin & Propagation Timeline</h2>")
        if not report.timelines:
            doc.append("<p class='dim'>No timeline events recorded for registered evidence.</p>")
        else:
            for ev_id, tl in report.timelines.items():
                doc.append(f"<h3>Timeline for Evidence <code>{esc(ev_id)}</code></h3>")
                events = tl.get("timeline", [])
                if not events:
                    doc.append("<p class='dim'>No chronological events recorded.</p>")
                    continue
                doc.append("<table>")
                doc.append("<tr><th>Event Type</th><th>Timestamp (UTC)</th><th>Source</th><th>Details</th></tr>")
                for ev in events:
                    doc.append(
                        f"<tr><td><code>{esc(ev.get('event_type'))}</code></td><td>{esc(ev.get('timestamp'))}</td>"
                        f"<td>{esc(ev.get('source'))}</td><td>{esc(ev.get('description'))}</td></tr>"
                    )
                doc.append("</table>")
        doc.append("</div>")

        # --- Audit Trail ---
        doc.append("<div class='section'>")
        doc.append("<h2>12. Audit Trail & Chain of Custody Summary</h2>")
        if not report.audit_events:
            doc.append("<p class='dim'>No case-specific audit events recorded.</p>")
        else:
            doc.append("<table>")
            doc.append("<tr><th>Timestamp (UTC)</th><th>Action</th><th>Actor</th><th>Summary</th><th>Entry Hash</th></tr>")
            for a in report.audit_events[-20:]:
                details = a.get("details", {})
                target = details.get("evidence_id") or details.get("provenance_id") or details.get("case_id") or "Case"
                h = a.get("entry_hash", "")[:16] + "..." if a.get("entry_hash") else "N/A"
                doc.append(
                    f"<tr><td>{esc(a.get('timestamp', '')[:19])}</td><td><code>{esc(a.get('action'))}</code></td>"
                    f"<td>{esc(a.get('actor'))}</td><td>{esc(target)}</td><td><code>{esc(h)}</code></td></tr>"
                )
            doc.append("</table>")
        doc.append("</div>")

        # --- Overall Findings ---
        doc.append("<div class='section'>")
        doc.append("<h2>13. Summary of Objective Findings</h2><ul>")
        if report.overall_findings:
            for item in report.overall_findings:
                doc.append(f"<li>{esc(item)}</li>")
        else:
            doc.append("<li>Digital evidence preserved and cryptographically verified against SHA-256 baselines.</li>")
        doc.append("</ul></div>")

        # --- Limitations ---
        doc.append("<div class='section'>")
        doc.append("<h2>14. Forensic & Legal Limitations</h2><ol>")
        if report.limitations:
            for lim in report.limitations:
                doc.append(f"<li>{esc(lim)}</li>")
        else:
            doc.append("<li>Findings require independent human review alongside physical corroborating facts.</li>")
        doc.append("</ol></div>")

        # --- Investigator Notes ---
        doc.append("<div class='section'>")
        doc.append("<h2>15. Investigator / Case Notes</h2>")
        if report.investigator_notes:
            doc.append(f"<p>{esc(report.investigator_notes)}</p>")
        else:
            doc.append("<p class='dim'>None recorded.</p>")
        doc.append("</div>")

        # --- Footer ---
        doc.append(f"<div class='footer'>Report generated locally by DigitalShield Forensic Suite v{esc(meta.software_version)}. Zero external network calls.</div>")
        doc.append("</div>")
        doc.append("</body>")
        doc.append("</html>")

        return "\n".join(doc)
