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
def check(
    path: Path = typer.Option(..., "--path", "-p", help="Path to review"),
    threshold: str = typer.Option("warning", "--threshold", "-t", help="Fail if findings at this level or above"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """CI-friendly check: non-zero exit if issues found above threshold.

    Use in CI: codeguardian check --path ./src --threshold critical
    Exit codes: 0=clean, 1=error, 2=issues found
    """
    settings = load_config(config_path)
    settings.fail_on = Severity(threshold)

    scope = build_scope(path=path)
    findings = asyncio.run(_run_review(scope, settings))

    if findings:
        reporter = Reporter(findings)
        _print_summary(reporter)
        if _has_finding_at_severity(findings, Severity(threshold)):
            raise typer.Exit(code=2)

    console.print("[green]Check passed[/green]")


@app.command()
def pr_review(
    pr_number: Optional[int] = typer.Option(None, "--pr", help="PR number (auto-detect from CI if omitted)"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Repository (owner/name)"),
    config_path: Optional[Path] = typer.Option(None, "--config", "-c"),
) -> None:
    """Review a GitHub Pull Request and post results as a comment.

    Requires GITHUB_TOKEN env var or gh CLI to be authenticated.
    Uses CI environment variables when running in GitHub Actions.
    """
    import os
    import subprocess
    import sys

    settings = load_config(config_path)

    # Detect PR info
    if not pr_number:
        pr_number = _detect_pr_number()
    if not repo:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not pr_number or not repo:
        console.print("[red]Could not detect PR number or repo. "
                       "Use --pr and --repo options.[/red]")
        raise typer.Exit(code=1)

    # Get PR diff
    diff = _get_pr_diff(pr_number, repo)
    if not diff:
        console.print("[red]Could not fetch PR diff.[/red]")
        raise typer.Exit(code=1)

    # Build scope and review
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        diff_file = Path(td) / "pr.diff"
        diff_file.write_text(diff, encoding="utf-8")
        scope = build_scope_from_diff(diff)
        findings = asyncio.run(_run_review(scope, settings))

    reporter = Reporter(findings)
    report = reporter.to_markdown(title=f"## CodeGuardian Review — PR #{pr_number}")

    # Post to PR
    _post_pr_comment(pr_number, repo, report)

    _print_summary(reporter)


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


# ── PR Review helpers ────────────────────────────────────────────

def _detect_pr_number() -> int | None:
    """Detect PR number from CI environment or gh CLI."""
    import os

    # GitHub Actions
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        import json
        try:
            event = json.loads(Path(event_path).read_text())
            if "pull_request" in event:
                return event["pull_request"]["number"]
            if "number" in event:
                return event["number"]
        except Exception:
            pass

    # Azure DevOps / GitLab / etc.
    for var in ["SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", "CI_MERGE_REQUEST_IID"]:
        val = os.environ.get(var)
        if val:
            return int(val)

    return None


def _get_pr_diff(pr_number: int, repo: str) -> str | None:
    """Get PR diff via gh CLI or GitHub API."""
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = repo.strip()

    # Try gh CLI first
    import shutil
    if shutil.which("gh"):
        import subprocess
        result = subprocess.run(
            ["gh", "pr", "diff", str(pr_number), "--repo", repo],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return result.stdout

    # Fallback to API
    if token:
        import httpx
        try:
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3.diff",
                },
                timeout=30,
            )
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass

    return None


def _post_pr_comment(pr_number: int, repo: str, body: str) -> None:
    """Post or update a review comment on a PR."""
    import os

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        console.print("[yellow]No GITHUB_TOKEN; skipping PR comment.[/yellow]")
        return

    import httpx
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }
    api_base = f"https://api.github.com/repos/{repo}"

    # Truncate body if needed
    if len(body) > 60000:
        body = body[:60000] + "\n\n... (truncated)"

    try:
        # List existing comments
        resp = httpx.get(
            f"{api_base}/issues/{pr_number}/comments",
            headers=headers, timeout=15,
        )
        comments = resp.json() if resp.status_code == 200 else []

        bot_comment_id = None
        for c in comments:
            if "CodeGuardian Review" in c.get("body", ""):
                bot_comment_id = c["id"]
                break

        if bot_comment_id:
            resp = httpx.patch(
                f"{api_base}/issues/comments/{bot_comment_id}",
                headers=headers, json={"body": body}, timeout=15,
            )
        else:
            resp = httpx.post(
                f"{api_base}/issues/{pr_number}/comments",
                headers=headers, json={"body": body}, timeout=15,
            )

        if resp.status_code in (200, 201):
            console.print("[green]PR comment posted successfully[/green]")
        else:
            console.print(f"[yellow]Failed to post PR comment: {resp.status_code}[/yellow]")

    except Exception as e:
        console.print(f"[yellow]Error posting PR comment: {e}[/yellow]")


def build_scope_from_diff(diff_text: str) -> ChangeScope:
    """Parse a unified diff into a ChangeScope."""
    import re

    changed_files: list[ChangedFile] = []
    current_file = None
    additions = 0
    deletions = 0

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            if current_file:
                changed_files.append(ChangedFile(
                    path=current_file,
                    status="modified",
                    additions=additions,
                    deletions=deletions,
                ))
            current_file = None
            additions = 0
            deletions = 0
        elif line.startswith("+++ "):
            parts = line[4:].strip().split("/", 1)
            current_file = parts[1] if len(parts) > 1 else parts[0]
        elif current_file:
            if line.startswith("+") and not line.startswith("+++"):
                additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                deletions += 1

    if current_file:
        changed_files.append(ChangedFile(
            path=current_file,
            status="modified",
            additions=additions,
            deletions=deletions,
        ))

    return ChangeScope(changed_files=changed_files, diff_text=diff_text)


if __name__ == "__main__":
    app()
