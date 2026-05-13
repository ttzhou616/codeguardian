"""Style checker agent — naming conventions, formatting, function length, consistency."""

from __future__ import annotations

import re
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import RuleEngine, SKIP_EXTENSIONS
from codeguardian.scanner.rules import SecurityRule, load_style_rules


class StyleCheckerAgent(BaseAgent):
    """Checks code style: naming conventions, function length, disallowed patterns."""

    topic = "style_checker"

    def __init__(self, name="style_checker", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)

    async def setup(self) -> None:
        rules = load_style_rules()
        self.max_lines_rules = [r for r in rules if r.max_lines]
        pattern_rules = [r for r in rules if r.patterns and not r.max_lines]
        self.engine = RuleEngine(pattern_rules, default_category=FindingCategory.STYLE)
        await self.log("info", f"Style checker loaded {len(rules)} rules "
                              f"({len(pattern_rules)} pattern, {len(self.max_lines_rules)} length)")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        if not hasattr(self, "engine") or self.engine is None:
            await self.setup()

        files = scope.file_paths
        if not files:
            return []

        await self.log("info", f"Checking style on {len(files)} file(s)")

        # 1. Pattern-based rules via engine (naming, disallowed keywords)
        findings = await self.engine.scan_files(files)

        # 2. Function-length checks (requires structural awareness)
        for rule in self.max_lines_rules:
            for fp in files:
                findings.extend(self._check_function_length(fp, rule))

        for f in findings:
            f.category = FindingCategory.STYLE

        await self.log("info", f"Found {len(findings)} style issue(s)")
        return findings

    def _check_function_length(self, file_path: str, rule: SecurityRule) -> list[Finding]:
        """Check that functions don't exceed max_lines by tracking indentation."""
        path = Path(file_path)
        ext = path.suffix.lower()
        if rule.file_extensions and ext not in rule.file_extensions:
            return []
        if ext in SKIP_EXTENSIONS or not path.exists():
            return []

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        except Exception:
            return []

        max_lines = rule.max_lines or 50
        findings: list[Finding] = []
        func_start: int | None = None
        func_name = ""
        func_indent = 0

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped == "":
                continue

            current_indent = len(line) - len(line.lstrip(" "))

            # Detect function definition
            func_match = re.match(
                r"(?:def|fun\b|function|func|fn)\s+(\w+)",
                stripped,
            )
            if func_match:
                # Close previous function
                if func_start is not None:
                    func_lines = i - func_start
                    if func_lines > max_lines:
                        findings.append(self._make_length_finding(
                            file_path, func_start, i - 1, func_name, func_lines, rule,
                        ))
                func_start = i
                func_name = func_match.group(1)
                func_indent = current_indent
                continue

            # Detect end of function: line at same or lower indent than function def
            if func_start is not None and current_indent <= func_indent and stripped != "":
                # Allow else/elif/except/finally at same level
                if not re.match(r"^(?:else|elif|except|finally|catch)\b", stripped):
                    func_lines = i - func_start
                    if func_lines > max_lines:
                        findings.append(self._make_length_finding(
                            file_path, func_start, i - 1, func_name, func_lines, rule,
                        ))
                    func_start = None

        # Handle last function in file
        if func_start is not None:
            func_lines = len(lines) - func_start + 1
            if func_lines > max_lines:
                findings.append(self._make_length_finding(
                    file_path, func_start, len(lines), func_name, func_lines, rule,
                ))

        return findings

    def _make_length_finding(
        self, file_path: str, start: int, end: int,
        name: str, lines: int, rule: SecurityRule,
    ) -> Finding:
        return Finding(
            file_path=file_path,
            line_start=start,
            line_end=end,
            title=f"Function '{name}' is too long ({lines} lines)",
            description=f"Function exceeds the maximum of {rule.max_lines} lines.",
            severity=rule.severity,
            category=FindingCategory.STYLE,
            suggestion=rule.suggestion,
            rule_id=rule.rule_id,
        )
