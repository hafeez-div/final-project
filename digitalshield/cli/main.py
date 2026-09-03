"""
Main CLI entry point for DigitalShield application.
"""

import os
import sys
from pathlib import Path
from typing import List, Optional
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from digitalshield.case_manager.manager import CaseManager
from digitalshield.evidence.manager import EvidenceManager
from digitalshield.fingerprinting.service import FingerprintService
from digitalshield.detection.ela import ELADetector
from digitalshield.detection.deepfake import DeepfakeAssessmentService
from digitalshield.provenance.service import ProvenanceService
from digitalshield.reporting.service import ReportingService

# Reconfigure stdout to UTF-8 on Windows if needed
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

console = Console(safe_box=True, width=120)



@click.group()
@click.version_option(version="0.1.0", prog_name="DigitalShield")
def cli():
    """DigitalShield - Defensive Digital Forensics & Evidence Verification Suite."""
    pass


# ==========================================
# Case Commands
# ==========================================

@cli.group()
def case():
    """Manage forensic investigation cases."""
    pass


@case.command("create")
@click.option(
    "-n", "--name",
    type=str,
    prompt="Case Name",
    default="Default Forensic Case",
    help="Name or title of the investigation case."
)
@click.option(
    "-i", "--investigator",
    type=str,
    default="Unassigned",
    help="Name or email of lead investigator."
)
@click.option(
    "-d", "--description",
    type=str,
    default="",
    help="Case description or initial notes."
)
def case_create(name: str, investigator: str, description: str):
    """Create a new forensic case and initialize local vault structure."""
    try:
        manager = CaseManager()
        case_obj = manager.create_case(
            name=name,
            investigator=investigator,
            description=description
        )

        content = (
            f"[bold green]+ Case created successfully[/bold green]\n\n"
            f"[bold white]Case ID:[/bold white]     [cyan]{case_obj.case_id}[/cyan]\n"
            f"[bold white]Name:[/bold white]        {case_obj.name}\n"
            f"[bold white]Investigator:[/bold white] {case_obj.investigator}\n"
            f"[bold white]Status:[/bold white]       [green]{case_obj.status}[/green]\n"
            f"[bold white]Created At:[/bold white]   {case_obj.created_at}\n"
            f"[bold white]Vault Path:[/bold white]   [dim]{case_obj.vault_path}[/dim]"
        )

        console.print(Panel(content, title="[bold blue]DigitalShield Case Initialized[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error creating case:[/bold red] {e}")
        sys.exit(1)


@case.command("list")
def case_list():
    """List all registered forensic cases."""
    try:
        manager = CaseManager()
        cases = manager.list_cases()

        if not cases:
            console.print("[yellow]No cases found. Create one using 'digitalshield case create'.[/yellow]")
            return

        table = Table(title="Registered Forensic Cases")
        table.add_column("Case ID", style="cyan", no_wrap=True)
        table.add_column("Name", style="white")
        table.add_column("Investigator", style="magenta")
        table.add_column("Status", style="green")
        table.add_column("Evidence Count", justify="right")
        table.add_column("Created At", style="dim")

        for c in cases:
            table.add_row(
                c.case_id,
                c.name,
                c.investigator,
                c.status,
                str(c.evidence_count),
                c.created_at[:19].replace("T", " ")
            )

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error listing cases:[/bold red] {e}")
        sys.exit(1)


# ==========================================
# Evidence Commands
# ==========================================

@cli.group()
def evidence():
    """Import, list, and inspect forensic evidence."""
    pass


@evidence.command("import")
@click.argument("file_path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option(
    "-c", "--case", "case_id",
    type=str,
    required=True,
    help="Target Case ID (e.g. DS-2026-000001)."
)
def evidence_import(file_path: Path, case_id: str):
    """Import and preserve a file as forensic evidence."""
    try:
        manager = EvidenceManager()
        ev_obj = manager.import_evidence(file_path=file_path, case_id=case_id)

        content = (
            f"[bold green]+ Evidence imported and preserved successfully[/bold green]\n\n"
            f"[bold white]Evidence ID:[/bold white]       [cyan]{ev_obj.evidence_id}[/cyan]\n"
            f"[bold white]Case ID:[/bold white]           {ev_obj.case_id}\n"
            f"[bold white]Original File:[/bold white]     {ev_obj.original_filename}\n"
            f"[bold white]File Size:[/bold white]         {ev_obj.file_size:,} bytes\n"
            f"[bold white]MIME Type:[/bold white]         {ev_obj.mime_type}\n"
            f"[bold white]SHA-256 Digest:[/bold white]     [yellow]{ev_obj.sha256}[/yellow]\n"
            f"[bold white]Status:[/bold white]             [green]{ev_obj.status}[/green]\n"
            f"[bold white]Preserved Path:[/bold white]     [dim]{ev_obj.stored_path}[/dim]"
        )

        console.print(Panel(content, title="[bold blue]DigitalShield Evidence Ingestion[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error importing evidence:[/bold red] {e}")
        sys.exit(1)


@evidence.command("list")
@click.option(
    "-c", "--case", "case_id",
    type=str,
    required=True,
    help="Target Case ID."
)
def evidence_list(case_id: str):
    """List all evidence items ingested into a specific case."""
    try:
        manager = EvidenceManager()
        items = manager.list_evidence(case_id)

        if not items:
            console.print(f"[yellow]No evidence items found for case '{case_id}'.[/yellow]")
            return

        table = Table(title=f"Evidence Items in Case {case_id}")
        table.add_column("Evidence ID", style="cyan", no_wrap=True)
        table.add_column("Original Filename", style="white", no_wrap=True)
        table.add_column("File Size", justify="right", no_wrap=True)
        table.add_column("MIME Type", style="magenta", no_wrap=True)
        table.add_column("SHA-256 Digest", style="yellow", no_wrap=True)
        table.add_column("Status", style="green", no_wrap=True)


        for item in items:
            table.add_row(
                item.evidence_id,
                item.original_filename,
                f"{item.file_size:,} B",
                item.mime_type,
                f"{item.sha256[:16]}...",
                item.status
            )

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error listing evidence:[/bold red] {e}")
        sys.exit(1)


@evidence.command("show")
@click.argument("evidence_id", type=str)
def evidence_show(evidence_id: str):
    """Show detailed metadata and preservation records for an evidence ID."""
    try:
        manager = EvidenceManager()
        ev_obj = manager.get_evidence(evidence_id)

        if not ev_obj:
            console.print(f"[bold red]Error retrieving evidence:[/bold red] Evidence ID '{evidence_id}' not found.")
            sys.exit(1)

        content = (
            f"[bold white]Evidence ID:[/bold white]       [cyan]{ev_obj.evidence_id}[/cyan]\n"
            f"[bold white]Case ID:[/bold white]           {ev_obj.case_id}\n"
            f"[bold white]Original Filename:[/bold white] {ev_obj.original_filename}\n"
            f"[bold white]Stored Filename:[/bold white]   {ev_obj.stored_filename}\n"
            f"[bold white]File Size:[/bold white]         {ev_obj.file_size:,} bytes\n"
            f"[bold white]MIME Type:[/bold white]         {ev_obj.mime_type}\n"
            f"[bold white]Import Timestamp:[/bold white]  {ev_obj.import_timestamp}\n"
            f"[bold white]SHA-256 Digest:[/bold white]     [yellow]{ev_obj.sha256}[/yellow]\n"
            f"[bold white]Status:[/bold white]             [green]{ev_obj.status}[/green]\n"
            f"[bold white]Vault Path:[/bold white]         [dim]{ev_obj.stored_path}[/dim]"
        )

        console.print(Panel(content, title=f"[bold blue]Evidence Details - {ev_obj.evidence_id}[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error retrieving evidence:[/bold red] {e}")
        sys.exit(1)


@evidence.command("fingerprint")
@click.argument("evidence_id", type=str)
def evidence_fingerprint(evidence_id: str):
    """Generate and display perceptual fingerprints (aHash, dHash, pHash) for an evidence item."""
    try:
        service = FingerprintService()
        fp = service.generate_fingerprints(evidence_id)

        content = (
            f"[bold white]Evidence ID:[/bold white]   [cyan]{fp.evidence_id}[/cyan]\n"
            f"[bold white]Filename:[/bold white]      {fp.original_filename or 'Unknown'}\n\n"
            f"[bold white]aHash:[/bold white]         [yellow]{fp.ahash}[/yellow]\n"
            f"[bold white]dHash:[/bold white]         [yellow]{fp.dhash}[/yellow]\n"
            f"[bold white]pHash:[/bold white]         [yellow]{fp.phash}[/yellow]\n\n"
            f"[dim italic]Disclaimer: {fp.disclaimer}[/dim italic]"
        )

        console.print(Panel(content, title="[bold blue]Perceptual Fingerprints[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error generating fingerprints:[/bold red] {e}")
        sys.exit(1)


@evidence.command("compare")
@click.argument("evidence_id_1", type=str)
@click.argument("evidence_id_2", type=str)
def evidence_compare(evidence_id_1: str, evidence_id_2: str):
    """Compare perceptual fingerprints between two evidence items."""
    try:
        service = FingerprintService()
        res = service.compare_fingerprints(evidence_id_1, evidence_id_2)

        content = (
            f"[bold white]Evidence A:[/bold white]            [cyan]{res.evidence_id_a}[/cyan] ({res.filename_a or 'Unknown'})\n"
            f"[bold white]Evidence B:[/bold white]            [cyan]{res.evidence_id_b}[/cyan] ({res.filename_b or 'Unknown'})\n\n"
            f"[bold white]aHash distance:[/bold white]        {res.metrics['aHash'].hamming_distance} / 64  "
            f"[dim](Similarity: {res.metrics['aHash'].normalized_similarity * 100:.1f}%)[/dim]\n"
            f"[bold white]dHash distance:[/bold white]        {res.metrics['dHash'].hamming_distance} / 64  "
            f"[dim](Similarity: {res.metrics['dHash'].normalized_similarity * 100:.1f}%)[/dim]\n"
            f"[bold white]pHash distance:[/bold white]        {res.metrics['pHash'].hamming_distance} / 64  "
            f"[dim](Similarity: {res.metrics['pHash'].normalized_similarity * 100:.1f}%)[/dim]\n\n"
            f"[bold white]Overall Similarity:[/bold white]    [bold yellow]{res.overall_similarity * 100:.1f}%[/bold yellow]\n"
            f"[bold white]Assessment:[/bold white]            [bold green]{res.assessment}[/bold green]\n\n"
            f"[dim italic]Disclaimer: {res.disclaimer}[/dim italic]"
        )

        console.print(Panel(content, title="[bold blue]Perceptual Similarity Comparison[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error comparing evidence fingerprints:[/bold red] {e}")
        sys.exit(1)


# ==========================================
# Analysis & Detection Commands
# ==========================================

@cli.group()
def analyze():
    """Perform forensic analysis and manipulation detection on evidence."""
    pass


@analyze.command("ela")
@click.argument("evidence_id", type=str)
@click.option(
    "-q", "--quality",
    type=int,
    default=90,
    help="JPEG recompression quality for ELA (default: 90)."
)
def analyze_ela(evidence_id: str, quality: int):
    """Execute Error Level Analysis (ELA) to detect potential image manipulation anomalies."""
    try:
        detector = ELADetector()
        res = detector.analyze_evidence(evidence_id=evidence_id, quality=quality)

        content = (
            f"[bold white]Evidence ID:[/bold white]       [cyan]{res.evidence_id}[/cyan]\n"
            f"[bold white]Filename:[/bold white]          {res.original_filename or 'Unknown'}\n"
            f"[bold white]Image Dimensions:[/bold white]  {res.image_width} x {res.image_height} px ({res.color_mode})\n\n"
            f"[bold white]Mean ELA Level:[/bold white]    {res.mean_error:.4f}\n"
            f"[bold white]Maximum ELA Level:[/bold white] {res.max_error:.4f}\n"
            f"[bold white]StdDev Error:[/bold white]      {res.statistics.stddev_error:.4f}\n"
            f"[bold white]High Error Pixels:[/bold white] {res.statistics.high_error_pixels:,} ({res.statistics.high_error_ratio * 100:.2f}%)\n\n"
            f"[bold white]Indicator Score:[/bold white]   [bold yellow]{res.anomaly_score:.4f}[/bold yellow] (0.0 = uniform, 1.0 = high anomaly)\n"
            f"[bold white]Confidence:[/bold white]        [green]{res.confidence * 100:.1f}%[/green]\n"
            f"[bold white]Assessment:[/bold white]        [bold cyan]{res.assessment}[/bold cyan]\n\n"
            f"[dim italic]Limitations: {res.disclaimer}[/dim italic]"
        )

        console.print(Panel(content, title="[bold blue]Error Level Analysis (ELA) Report[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error executing ELA analysis:[/bold red] {e}")
        sys.exit(1)


@analyze.command("deepfake")
@click.argument("evidence_id", type=str)
def analyze_deepfake(evidence_id: str):
    """Perform probabilistic AI-based synthetic media / deepfake assessment."""
    try:
        service = DeepfakeAssessmentService()
        res = service.assess_evidence(evidence_id=evidence_id)

        indicators_text = "\n".join([f"  • {ind}" for ind in res.indicators]) if res.indicators else "  None"
        limitations_text = "\n".join([f"  • {lim}" for lim in res.limitations]) if res.limitations else "  None"

        content = (
            f"[bold white]Evidence ID:[/bold white]          [cyan]{res.evidence_id}[/cyan]\n"
            f"[bold white]Filename:[/bold white]             {res.original_filename or 'Unknown'}\n\n"
            f"[bold white]Detector:[/bold white]             {res.detector_name}\n"
            f"[bold white]Detector Type:[/bold white]        [yellow]{res.detector_type.value.title()}[/yellow]\n\n"
            f"[bold white]Synthetic Probability:[/bold white] [bold yellow]{res.synthetic_probability:.2f}[/bold yellow] (0.0 to 1.0)\n"
            f"[bold white]Confidence:[/bold white]           [green]{res.confidence * 100:.1f}%[/green]\n\n"
            f"[bold white]Assessment:[/bold white]\n[bold cyan]{res.assessment}[/bold cyan]\n\n"
            f"[bold white]Indicators:[/bold white]\n{indicators_text}\n\n"
            f"[bold white]Limitations:[/bold white]\n[dim italic]{limitations_text}[/dim italic]\n\n"
            f"[dim]Important: The displayed confidence must NOT be interpreted as certainty that the image is fake. "
            f"Assessments are probabilistic indicators and never infer authorship, identity, or criminal responsibility.[/dim]"
        )

        console.print(Panel(content, title="[bold blue]AI Deepfake Assessment[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error executing deepfake assessment:[/bold red] {e}")
        sys.exit(1)


# ==========================================
# Provenance Commands
# ==========================================

@cli.group()
def provenance():
    """Analyze public URL provenance and origin timelines."""
    pass


@provenance.command("add")
@click.argument("evidence_id", type=str)
@click.argument("public_url", type=str)
@click.option("-a", "--account", "account_name", type=str, default=None, help="Publicly visible account name or handle.")
@click.option("-m", "--media-url", "media_url", type=str, default=None, help="Public media URL for visual similarity matching.")
@click.option("-t", "--source-timestamp", "source_timestamp", type=str, default=None, help="Explicit visible timestamp from source page.")
@click.option("-n", "--notes", type=str, default=None, help="Investigator notes.")
def provenance_add(
    evidence_id: str,
    public_url: str,
    account_name: Optional[str],
    media_url: Optional[str],
    source_timestamp: Optional[str],
    notes: Optional[str]
):
    """Record a public URL provenance observation for an evidence item."""
    try:
        service = ProvenanceService()
        rec = service.record_provenance(
            evidence_id=evidence_id,
            source_url=public_url,
            observed_account_name=account_name,
            media_url=media_url,
            source_timestamp=source_timestamp,
            notes=notes
        )

        sim_str = f"{rec.similarity_score * 100:.1f}%" if rec.similarity_score is not None else "N/A"
        match_str = rec.matching_method or "None"
        media_match_status = "Matched" if rec.similarity_score is not None else "No media compared"
        limitations_text = "\n".join([f"  • {lim}" for lim in rec.limitations]) if rec.limitations else "  None"

        content = (
            f"[bold white]Provenance ID:[/bold white]     [cyan]{rec.provenance_id}[/cyan]\n"
            f"[bold white]Evidence ID:[/bold white]       [cyan]{rec.evidence_id}[/cyan]\n"
            f"[bold white]Source URL:[/bold white]        {rec.source_url}\n"
            f"[bold white]Source Domain:[/bold white]     {rec.source_domain}\n"
            f"[bold white]Discovery Time:[/bold white]    {rec.discovery_timestamp}\n"
            f"[bold white]Observed Account:[/bold white]  {rec.observed_account_name or 'Unknown'}\n"
            f"[bold white]Media Match:[/bold white]       {media_match_status}\n"
            f"[bold white]Similarity:[/bold white]        [bold yellow]{sim_str}[/bold yellow]\n"
            f"[bold white]Matching Method:[/bold white]   {match_str}\n\n"
            f"[bold white]Assessment:[/bold white]\n[bold cyan]{rec.assessment}[/bold cyan]\n\n"
            f"[bold white]Limitations:[/bold white]\n[dim italic]{limitations_text}[/dim italic]"
        )

        console.print(Panel(content, title="[bold blue]Provenance Record[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error recording provenance:[/bold red] {e}")
        sys.exit(1)


@provenance.command("list")
@click.option("-c", "--case", "case_id", type=str, required=True, help="Target Case ID.")
def provenance_list(case_id: str):
    """List all public URL provenance records associated with a case."""
    try:
        service = ProvenanceService()
        records = service.list_provenance_by_case(case_id)

        if not records:
            console.print(f"[yellow]No provenance records found for case '{case_id}'.[/yellow]")
            return

        table = Table(title=f"Public URL Provenance Records in Case {case_id}")
        table.add_column("Provenance ID", style="cyan", no_wrap=True)
        table.add_column("Evidence ID", style="cyan", no_wrap=True)
        table.add_column("Domain", style="white")
        table.add_column("Observed Account", style="magenta")
        table.add_column("Similarity", style="yellow", justify="right")
        table.add_column("Discovery Time", style="dim")

        for r in records:
            sim_display = f"{r.similarity_score * 100:.1f}%" if r.similarity_score is not None else "N/A"
            table.add_row(
                r.provenance_id,
                r.evidence_id,
                r.source_domain,
                r.observed_account_name or "Unknown",
                sim_display,
                r.discovery_timestamp[:19].replace("T", " ")
            )

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error listing provenance records:[/bold red] {e}")
        sys.exit(1)


@provenance.command("show")
@click.argument("provenance_id", type=str)
def provenance_show(provenance_id: str):
    """Show detailed provenance record."""
    try:
        service = ProvenanceService()
        rec = service.get_provenance(provenance_id)

        if not rec:
            console.print(f"[bold red]Error:[/bold red] Provenance record '{provenance_id}' not found.")
            sys.exit(1)

        sim_str = f"{rec.similarity_score * 100:.1f}%" if rec.similarity_score is not None else "N/A"
        match_str = rec.matching_method or "None"
        media_match_status = "Matched" if rec.similarity_score is not None else "No media compared"
        limitations_text = "\n".join([f"  • {lim}" for lim in rec.limitations]) if rec.limitations else "  None"

        content = (
            f"[bold white]Provenance ID:[/bold white]     [cyan]{rec.provenance_id}[/cyan]\n"
            f"[bold white]Case ID:[/bold white]           {rec.case_id}\n"
            f"[bold white]Evidence ID:[/bold white]       [cyan]{rec.evidence_id}[/cyan]\n"
            f"[bold white]Source URL:[/bold white]        {rec.source_url}\n"
            f"[bold white]Source Domain:[/bold white]     {rec.source_domain}\n"
            f"[bold white]Page Title:[/bold white]        {rec.source_title or 'Unknown'}\n"
            f"[bold white]Discovery Time:[/bold white]    {rec.discovery_timestamp}\n"
            f"[bold white]Observed Account:[/bold white]  {rec.observed_account_name or 'Unknown'}\n"
            f"[bold white]Source Timestamp:[/bold white]  {rec.source_timestamp or 'Unknown / Unspecified'}\n"
            f"[bold white]Media Match:[/bold white]       {media_match_status}\n"
            f"[bold white]Similarity:[/bold white]        [bold yellow]{sim_str}[/bold yellow]\n"
            f"[bold white]Matching Method:[/bold white]   {match_str}\n\n"
            f"[bold white]Assessment:[/bold white]\n[bold cyan]{rec.assessment}[/bold cyan]\n\n"
            f"[bold white]Limitations:[/bold white]\n[dim italic]{limitations_text}[/dim italic]"
        )

        console.print(Panel(content, title=f"[bold blue]Provenance Record - {rec.provenance_id}[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error showing provenance record:[/bold red] {e}")
        sys.exit(1)


@provenance.command("timeline")
@click.argument("evidence_id", type=str)
def provenance_timeline(evidence_id: str):
    """Generate and display evidence-supported origin timeline."""
    try:
        service = ProvenanceService()
        timeline_data = service.get_provenance_timeline(evidence_id)

        table = Table(title=f"Origin Timeline for Evidence {evidence_id}")
        table.add_column("Event Type", style="cyan", no_wrap=True)
        table.add_column("Timestamp", style="yellow", no_wrap=True)
        table.add_column("Source / Location", style="white")
        table.add_column("Description / Assessment", style="dim")

        for event in timeline_data["timeline"]:
            table.add_row(
                event["event_type"],
                str(event.get("timestamp") or "Unknown"),
                event.get("source", "Internal Vault"),
                event.get("description", "")
            )

        console.print(table)
        console.print(f"[dim italic]Disclaimer: {timeline_data['disclaimer']}[/dim italic]")

    except Exception as e:
        console.print(f"[bold red]Error generating provenance timeline:[/bold red] {e}")
        sys.exit(1)


# ==========================================
# Report Commands
# ==========================================

@cli.group()
def report():
    """Generate, list, and inspect forensic analysis reports."""
    pass


@report.command("generate")
@click.argument("case_id", type=str)
@click.option(
    "-f", "--format", "report_format",
    type=click.Choice(["markdown", "html", "pdf", "all"], case_sensitive=False),
    default="all",
    help="Report output format: markdown, html, pdf, or all (default: all)."
)
def report_generate(case_id: str, report_format: str):
    """Generate a comprehensive forensic analysis report for a case."""
    try:
        service = ReportingService()
        rec, output_paths = service.generate_report(case_id=case_id, formats=report_format)

        files_list = "\n".join([f"  • [bold white]{fmt.upper()}:[/bold white] [dim]{p}[/dim]" for fmt, p in output_paths.items()])

        content = (
            f"[bold green]+ Forensic report generated successfully[/bold green]\n\n"
            f"[bold white]Report ID:[/bold white]          [cyan]{rec.report_id}[/cyan]\n"
            f"[bold white]Case ID:[/bold white]            {rec.case_id}\n"
            f"[bold white]Generation Time:[/bold white]    {rec.generation_timestamp}\n"
            f"[bold white]Formats Created:[/bold white]    {', '.join(rec.formats_generated).upper()}\n\n"
            f"[bold white]Generated Files:[/bold white]\n{files_list}\n\n"
            f"[dim italic]Reports are stored locally in .digitalshield_data/cases/{rec.case_id}/reports/[/dim italic]"
        )

        console.print(Panel(content, title="[bold blue]DigitalShield Forensic Report[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error generating forensic report:[/bold red] {e}")
        sys.exit(1)


@report.command("list")
@click.option("-c", "--case", "case_id", type=str, required=True, help="Target Case ID.")
def report_list(case_id: str):
    """List all generated forensic reports associated with a case."""
    try:
        service = ReportingService()
        reports = service.list_reports_by_case(case_id)

        if not reports:
            console.print(f"[yellow]No reports found for case '{case_id}'. Generate one using 'digitalshield report generate {case_id}'.[/yellow]")
            return

        table = Table(title=f"Generated Forensic Reports in Case {case_id}")
        table.add_column("Report ID", style="cyan", no_wrap=True)
        table.add_column("Case ID", style="white", no_wrap=True)
        table.add_column("Formats", style="magenta")
        table.add_column("Generated At", style="dim")
        table.add_column("Status", style="green")

        for r in reports:
            table.add_row(
                r.report_id,
                r.case_id,
                ", ".join(r.formats_generated).upper(),
                r.generation_timestamp[:19].replace("T", " "),
                r.status
            )

        console.print(table)

    except Exception as e:
        console.print(f"[bold red]Error listing reports:[/bold red] {e}")
        sys.exit(1)


@report.command("show")
@click.argument("report_id", type=str)
def report_show(report_id: str):
    """Show details and file paths of a generated forensic report."""
    try:
        service = ReportingService()
        rec = service.get_report(report_id)

        if not rec:
            console.print(f"[bold red]Error:[/bold red] Report ID '{report_id}' not found.")
            sys.exit(1)

        files_list = "\n".join([f"  • [bold white]{fmt.upper()}:[/bold white] [dim]{p}[/dim]" for fmt, p in rec.files.items()])

        content = (
            f"[bold white]Report ID:[/bold white]          [cyan]{rec.report_id}[/cyan]\n"
            f"[bold white]Case ID:[/bold white]            {rec.case_id}\n"
            f"[bold white]Generation Time:[/bold white]    {rec.generation_timestamp}\n"
            f"[bold white]Status:[/bold white]             [green]{rec.status}[/green]\n"
            f"[bold white]Formats:[/bold white]            {', '.join(rec.formats_generated).upper()}\n\n"
            f"[bold white]Report Files:[/bold white]\n{files_list}"
        )

        console.print(Panel(content, title=f"[bold blue]Report Details - {rec.report_id}[/bold blue]", expand=False))

    except Exception as e:
        console.print(f"[bold red]Error retrieving report:[/bold red] {e}")

# ==========================================
# GUI Command
# ==========================================

@cli.command("gui")
def launch_gui_command():
    """Launch the DigitalShield Desktop Graphical User Interface."""
    try:
        from digitalshield.gui.app import launch_gui
        launch_gui()
    except Exception as e:
        console.print(f"[bold red]Error launching GUI:[/bold red] {e}")
        sys.exit(1)


def main(args: Optional[List[str]] = None) -> int:
    """Entry point wrapper for script and package execution."""
    if args is not None:
        try:
            cli(args=args, standalone_mode=False)
            return 0
        except SystemExit as e:
            return e.code if isinstance(e.code, int) else 1
    else:
        cli()
        return 0


if __name__ == "__main__":
    sys.exit(main())
