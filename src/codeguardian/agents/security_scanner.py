"""Security scanner agent — SQL injection, XSS, secrets detection."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.knowledge.base import KnowledgeBase
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import RuleEngine
from codeguardian.scanner.rules import load_builtin_rules


class SecurityScannerAgent(BaseAgent):
    """Detects security vulnerabilities: SQL injection, XSS, hardcoded secrets, dangerous functions."""

    topic = "security_scanner"

    def __init__(self, name="security_scanner", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)
        self.engine: RuleEngine | None = None
        self.kb: KnowledgeBase | None = None

    async def setup(self) -> None:
        rules = load_builtin_rules()
        # Merge with custom rules from config if specified
        if self._config.custom_rules:
            rules = self._merge_custom_rules(rules)
        self.engine = RuleEngine(rules)
        self.kb = KnowledgeBase()
        await self.log("info", f"Security scanner loaded {len(rules)} rules")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        if not self.engine:
            self.engine = RuleEngine(load_builtin_rules())
        if not self.kb:
            self.kb = KnowledgeBase()

        files = scope.file_paths
        if not files:
            await self.log("info", "No files to scan")
            return []

        await self.log("info", f"Scanning {len(files)} file(s)")

        # Run built-in rule engine
        findings = await self.engine.scan_files(files)

        # Optionally augment with Semgrep
        if self._semgrep_available():
            try:
                semgrep_findings = await self._run_semgrep(files)
                findings = self._merge_findings(findings, semgrep_findings)
            except Exception:
                await self.log("warning", "Semgrep scan failed, using built-in results only")

        # Filter false positives
        findings = self.kb.filter_false_positives(findings)

        # Filter by severity threshold
        threshold = self._config.severity_threshold
        findings = [f for f in findings if self._severity_meets_threshold(f.severity, threshold)]

        await self.log("info", f"Found {len(findings)} issue(s)")
        return findings

    def _merge_custom_rules(self, rules: list) -> list:
        """Placeholder: merge user-provided custom rules with built-in rules."""
        return rules

    def _merge_findings(self, builtin: list[Finding], semgrep: list[Finding]) -> list[Finding]:
        """Merge semgrep results with built-in results, removing duplicates."""
        seen = {f.signature for f in builtin}
        for f in semgrep:
            if f.signature not in seen:
                seen.add(f.signature)
                builtin.append(f)
        return builtin

    @staticmethod
    def _semgrep_available() -> bool:
        """Check if semgrep CLI is installed."""
        return shutil.which("semgrep") is not None

    async def _run_semgrep(self, files: list[str]) -> list[Finding]:
        """Run Semgrep with bundled rules on the given files and parse results."""
        import os
        findings: list[Finding] = []

        # Find bundled rules directory
        rules_dir = os.environ.get(
            "CG_SEMGREP_RULES",
            str(Path(__file__).parent.parent.parent.parent / "rules" / "semgrep"),
        )

        cmd = [
            "semgrep", "scan",
            "--config", rules_dir,
            "--no-git-ignore",
            "--json",
            *files,
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode not in (0, 1):
            await self.log("warning", f"Semgrep failed: {stderr.decode()[:200]}")
            return findings

        try:
            results = json.loads(stdout.decode())
        except json.JSONDecodeError:
            return findings

        for result in results.get("results", []):
            findings.append(Finding(
                file_path=result["path"],
                line_start=result["start"]["line"],
                line_end=result["end"]["line"],
                col_start=result["start"].get("col"),
                col_end=result["end"].get("col"),
                title=result.get("check_id", "Semgrep finding"),
                description=result.get("extra", {}).get("message", ""),
                severity=self._map_semgrep_severity(result.get("extra", {}).get("severity", "")),
                category=FindingCategory.SECURITY,
                rule_id=result.get("check_id"),
            ))

        return findings

    @staticmethod
    def _map_semgrep_severity(sev: str) -> Severity:
        mapping = {"ERROR": Severity.CRITICAL, "WARNING": Severity.WARNING, "INFO": Severity.INFO}
        return mapping.get(sev.upper(), Severity.WARNING)

    @staticmethod
    def _severity_meets_threshold(severity: Severity, threshold: Severity) -> bool:
        order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.SUGGESTION: 2, Severity.INFO: 3}
        return order.get(severity, 3) <= order.get(threshold, 3)
