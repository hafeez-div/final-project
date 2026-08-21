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
