"""CLI entry point for CodeGuardian."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.prompt import Confirm, Prompt
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
    name="codeg",
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
    format: str = typer.Option(
        "markdown", "--format", "-f", help="Output format: markdown / json / sarif"
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path"
    ),
    only: Optional[str] = typer.Option(
        None, "--only", help="Run only a specific agent (e.g., performance_analyzer)"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Interactive mode: step-by-step prompts"
    ),
) -> None:
    """Review code and generate a report."""
    # Interactive mode
    if interactive or (not path and not diff):
        _review_interactive()
        return

    try:
        report_fmt = ReportFormat(format)
    except ValueError:
        console.print(f"[red]Invalid format: {format}. Use markdown / json / sarif[/red]")
        raise typer.Exit(code=1)

    settings = load_config(config_path)

    # Build change scope
    scope = build_scope(path=path, diff=diff)

    # Run review
    findings = asyncio.run(_run_review(scope, settings, only=only))

    # Generate report
    reporter = Reporter(findings)
    _output_report(reporter, report_fmt, settings, output)

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
    only: Optional[str] = typer.Option(None, "--only", help="Run only a specific agent"),
) -> None:
    """CI-friendly check: non-zero exit if issues found above threshold.

    Use in CI: codeg check --path ./src --threshold critical
    Exit codes: 0=clean, 1=error, 2=issues found
    """
    settings = load_config(config_path)
    settings.fail_on = Severity(threshold)

    scope = build_scope(path=path)
    findings = asyncio.run(_run_review(scope, settings, only=only))

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
def kb_stats() -> None:
    """Show knowledge base statistics."""
    try:
        from codeguardian.knowledge.vector_kb import VectorKnowledgeBase
        kb = VectorKnowledgeBase()
        stats = kb.get_stats()
        if stats.get("initialized"):
            console.print(f"[green]Vector KB:[/green] {stats.get('total_entries', 0)} entries, "
                          f"{stats.get('false_positives', 0)} false positives")
            console.print(f"  Storage: {stats.get('storage_path', 'N/A')}")
        else:
            console.print("[yellow]Vector KB not initialized (chromadb may not be installed)[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


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


def _review_interactive() -> None:
    """Interactive review walkthrough."""
    console.print()
    console.print("[bold cyan]CodeGuardian Interactive Review[/bold cyan]")
    console.print("─" * 40)
    console.print()

    # Step 1: Path
    while True:
        raw = Prompt.ask("[bold]1. 请输入要审查的目录或文件路径[/bold]").strip().strip('"')
        if not raw:
            console.print("[red]路径不能为空[/red]")
            continue
        p = Path(raw)
        if not p.exists():
            console.print(f"[red]路径不存在: {p}[/red]")
            continue
        break
    console.print(f"   [green]✓ {p}[/green]")
    console.print()

    # Step 2: Agent selection
    agents_display = [
        ("security_scanner",    "安全扫描 — SQL注入/密钥/XSS/命令注入"),
        ("static_analysis",     "静态分析 — 复杂度/嵌套/参数/异常"),
        ("style_checker",       "风格检查 — 命名/函数长度/禁用模式"),
        ("design_reviewer",     "设计审查 — 循环依赖/上帝类/高耦合"),
        ("test_reviewer",       "测试审查 — 缺失测试/断言/覆盖率"),
        ("performance_analyzer","性能分析 — N+1查询/循环拼接/反模式"),
    ]

    table = Table(title="2. 选择审查 Agent")
    table.add_column("#", style="dim", width=4)
    table.add_column("Agent", style="cyan")
    table.add_column("Description")
    for i, (name, desc) in enumerate(agents_display, 1):
        table.add_row(str(i), name, desc)
    table.add_row("0", "all", "全部运行")
    console.print(table)

    while True:
        choice = Prompt.ask("输入序号 (0=全部, 1-6)", default="0").strip()
        if choice == "0":
            only_agent = None
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(agents_display):
                only_agent = agents_display[idx][0]
                break
        except ValueError:
            pass
        console.print("[red]请输入 0-6[/red]")
    console.print(f"   [green]✓ {'全部' if not only_agent else only_agent}[/green]")
    console.print()

    # Step 3: Output format
    format_table = Table(title="3. 输出格式")
    format_table.add_column("#", style="dim", width=4)
    format_table.add_column("Format")
    format_table.add_column("Description")
    format_table.add_row("1", "markdown", "可读报告，适合终端查看和文件保存")
    format_table.add_row("2", "json",     "机器可读，适合 CI 流水线")
    format_table.add_row("3", "sarif",    "SARIF 标准格式，可导入 GitHub Code Scanning")
    console.print(format_table)

    fmt_choices = {"1": ReportFormat.MARKDOWN, "2": ReportFormat.JSON, "3": ReportFormat.SARIF}
    while True:
        fchoice = Prompt.ask("选择格式", default="1").strip()
        if fchoice in fmt_choices:
            fmt = fmt_choices[fchoice]
            break
        console.print("[red]请输入 1-3[/red]")
    console.print(f"   [green]✓ {fmt.value}[/green]")
    console.print()

    # Step 4: Output file (optional)
    save = Confirm.ask("4. 保存到文件？", default=True)
    output_path: Path | None = None
    if save:
        ext_map = {ReportFormat.MARKDOWN: "md", ReportFormat.JSON: "json", ReportFormat.SARIF: "sarif"}
        default_name = f"review_report.{ext_map[fmt]}"
        raw = Prompt.ask("文件名", default=default_name)
        output_path = Path(raw).resolve()
        console.print(f"   [green]✓ {output_path}[/green]")
    console.print()

    # ── Confirm and run ──────────────────────────────────────────
    console.print("─" * 40)
    if not Confirm.ask("[bold]开始审查？[/bold]", default=True):
        console.print("[yellow]已取消[/yellow]")
        return
    console.print()

    # Run
    settings = load_config()
    settings.report_format = fmt
    scope = build_scope(path=p)
    findings = asyncio.run(_run_review(scope, settings, only=only_agent))
    reporter = Reporter(findings)
    _print_summary(reporter)

    if output_path:
        reporter.write(output_path, fmt.value)
        console.print(f"[green]报告已保存至: {output_path}[/green]")
    else:
        formatters = {
            ReportFormat.MARKDOWN: reporter.to_markdown,
            ReportFormat.JSON: reporter.to_json,
            ReportFormat.SARIF: reporter.to_sarif,
        }
        console.print(formatters[fmt]())


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


async def _run_review(
    scope: ChangeScope, settings: CodeGuardianSettings, only: str | None = None,
) -> list:
    """Set up the orchestrator with all agents and run review."""
    orchestrator = Orchestrator(settings)

    all_agents = {
        "static_analysis": StaticAnalysisAgent("static_analysis", config=settings.agents["static_analysis"]),
        "security_scanner": SecurityScannerAgent("security_scanner", config=settings.agents["security_scanner"]),
        "design_reviewer": DesignReviewerAgent("design_reviewer", config=settings.agents["design_reviewer"]),
        "test_reviewer": TestReviewerAgent("test_reviewer", config=settings.agents["test_reviewer"]),
        "performance_analyzer": PerformanceAnalyzerAgent("performance_analyzer", config=settings.agents["performance_analyzer"]),
        "style_checker": StyleCheckerAgent("style_checker", config=settings.agents["style_checker"]),
    }

    if only:
        agent = all_agents.get(only)
        if agent is None:
            names = ", ".join(all_agents)
            console.print(f"[red]Unknown agent '{only}'. Available: {names}[/red]")
            raise typer.Exit(code=1)
        orchestrator.register(agent)
    else:
        orchestrator.register_all(list(all_agents.values()))

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
