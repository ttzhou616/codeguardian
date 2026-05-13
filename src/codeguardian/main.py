"""CLI entry point for CodeGuardian."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from codeguardian import __version__
from codeguardian.agents import (
    DesignReviewerAgent,
    PerformanceAnalyzerAgent,
    SecurityScannerAgent,
    StaticAnalysisAgent,
    StyleCheckerAgent,
    TestReviewerAgent,
)
from codeguardian.config import CodeGuardianSettings, generate_default_config, load_config
from codeguardian.models.findings import ChangeScope, ChangedFile, ReportFormat, Severity
from codeguardian.orchestrator import Orchestrator
from codeguardian.reporter import Reporter

app = typer.Typer(
    name="codeguardian",
    help="Multi-agent collaborative code review system",
    add_completion=False,
)
console = Console()


def version_callback(value: bool) -> None:
    if value:
        console.print(f"CodeGuardian v{__version__}")
        raise typer.Exit()


@app.callback()
def callback(
    version: bool = typer.Option(
        None, "--version", callback=version_callback, help="Show version"
    ),
) -> None:
    pass


@app.command()
def init(
    output: Path = typer.Option(
        Path("./.codeguardian.yaml"),
        "--output",
        "-o",
        help="Path to write the config file",
    ),
) -> None:
    """Generate a default .codeguardian.yaml configuration file."""
    generate_default_config(output)
    console.print(f"[green]Config written to {output}[/green]")


@app.command()
def review(
    path: Optional[Path] = typer.Option(
        None, "--path", "-p", help="File or directory to review"
    ),
    diff: Optional[str] = typer.Option(
        None, "--diff", help="Git diff spec (e.g., HEAD~1..HEAD)"
    ),
    config_path: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config file"
    ),
    format: ReportFormat = typer.Option(
        ReportFormat.MARKDOWN, "--format", "-f", help="Output format"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
) -> None:
    """Review code and generate a report."""
    if not path and not diff:
        console.print("[red]Either --path or --diff must be specified[/red]")
        raise typer.Exit(code=1)

    settings = load_config(config_path)

    # Build change scope
    scope = build_scope(path=path, diff=diff)

    # Run review
    findings = asyncio.run(_run_review(scope, settings))

    # Generate report
    reporter = Reporter(findings)
    _output_report(reporter, format, settings, output)

    # Print summary
    _print_summary(reporter)

    # Exit code based on fail_on
    if settings.fail_on and _has_finding_at_severity(findings, settings.fail_on):
        raise typer.Exit(code=2)


@app.command()
def agents() -> None:
    """List available review agents."""
    table = Table(title="Available Agents")
    table.add_column("Agent", style="cyan")
    table.add_column("Description", style="white")

    agents_info = [
        ("static_analysis", "Complexity, dead code, type safety"),
        ("security_scanner", "SQL injection, XSS, hardcoded secrets"),
        ("design_reviewer", "SOLID, coupling, architecture patterns"),
        ("test_reviewer", "Coverage gaps, boundary conditions"),
        ("performance_analyzer", "N+1 queries, memory leaks, lock contention"),
        ("style_checker", "Naming conventions, formatting, consistency"),
    ]
    for name, desc in agents_info:
        table.add_row(name, desc)
    console.print(table)


def build_scope(
    path: Optional[Path] = None,
    diff: Optional[str] = None,
) -> ChangeScope:
    """Build a ChangeScope from CLI inputs."""
    changed_files: list[ChangedFile] = []

    if path:
        if path.is_file():
            changed_files.append(ChangedFile(
                path=str(path.resolve()),
                status="modified",
                language=path.suffix.lstrip("."),
            ))
        elif path.is_dir():
            for f in path.rglob("*"):
                if f.is_file() and not _is_hidden(f):
                    changed_files.append(ChangedFile(
                        path=str(f.resolve()),
                        status="modified",
                        language=f.suffix.lstrip("."),
                    ))

    return ChangeScope(changed_files=changed_files, diff_text=diff)


async def _run_review(scope: ChangeScope, settings: CodeGuardianSettings) -> list:
    """Set up the orchestrator with all agents and run review."""
    orchestrator = Orchestrator(settings)

    orchestrator.register_all([
        StaticAnalysisAgent("static_analysis", config=settings.agents["static_analysis"]),
        SecurityScannerAgent("security_scanner", config=settings.agents["security_scanner"]),
        DesignReviewerAgent("design_reviewer", config=settings.agents["design_reviewer"]),
        TestReviewerAgent("test_reviewer", config=settings.agents["test_reviewer"]),
        PerformanceAnalyzerAgent("performance_analyzer", config=settings.agents["performance_analyzer"]),
        StyleCheckerAgent("style_checker", config=settings.agents["style_checker"]),
    ])

    report = await orchestrator.review(scope)
    return report.findings


def _output_report(
    reporter: Reporter,
    fmt: ReportFormat,
    settings: CodeGuardianSettings,
    output_path: Optional[Path],
) -> None:
    """Write the report to stdout or file."""
    if output_path:
        reporter.write(output_path, fmt.value)
        console.print(f"[green]Report written to {output_path}[/green]")
    else:
        formatters = {
            ReportFormat.MARKDOWN: reporter.to_markdown,
            ReportFormat.JSON: reporter.to_json,
            ReportFormat.SARIF: reporter.to_sarif,
        }
        content = formatters[fmt]()
        console.print(content)


def _print_summary(reporter: Reporter) -> None:
    """Print a summary table to the console."""
    findings = reporter.findings
    if not findings:
        console.print("[green]No issues found.[/green]")
        return

    table = Table(title="Review Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1

    styles = {
        Severity.CRITICAL: "red",
        Severity.WARNING: "yellow",
        Severity.SUGGESTION: "green",
        Severity.INFO: "dim",
    }
    for sev, count in counts.items():
        if count > 0:
            table.add_row(f"[{styles[sev]}]{sev.value.capitalize()}[/{styles[sev]}]", str(count))

    console.print(table)
    console.print(f"Total: {len(findings)} finding(s)")


def _has_finding_at_severity(findings: list, severity: Severity) -> bool:
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.SUGGESTION: 2, Severity.INFO: 3}
    threshold = severity_order[severity]
    return any(severity_order[f.severity] <= threshold for f in findings)


def _is_hidden(path: Path) -> bool:
    """Check if any path component starts with a dot."""
    return any(part.startswith(".") for part in path.parts)


if __name__ == "__main__":
    app()
