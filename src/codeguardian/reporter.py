"""Reporter — generates output in Markdown, JSON, and SARIF formats."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from codeguardian.models.findings import Finding, Severity


class Reporter:
    """Formats ReviewReports for various output targets."""

    SEVERITY_ICON = {
        Severity.CRITICAL: "🔴",
        Severity.WARNING: "🟡",
        Severity.SUGGESTION: "🟢",
        Severity.INFO: "ℹ️",
    }

    def __init__(self, findings: list[Finding]):
        self.findings = findings

    def to_markdown(self, title: str = "CodeGuardian Review Report") -> str:
        """Generate a Markdown report."""
        lines = [
            f"# {title}",
            f"",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Total findings:** {len(self.findings)}",
            f"",
            f"## Summary",
            f"",
            self._severity_table(),
            f"",
            f"## Findings",
            f"",
        ]

        if not self.findings:
            lines.append("✅ No issues found.")
        else:
            grouped = self._group_by_file()
            for file_path, findings in grouped.items():
                lines.append(f"### `{file_path}` ({len(findings)} issue(s))")
                lines.append("")
                for f in findings:
                    icon = self.SEVERITY_ICON[f.severity]
                    lines.append(
                        f"**{icon} [{f.severity.value.upper()}] Line {f.line_start}-{f.line_end}** — {f.title}"
                    )
                    if f.description:
                        lines.append(f"> {f.description}")
                    if f.suggestion:
                        lines.append(f"```")
                        lines.append(f.suggestion)
                        lines.append(f"```")
                    lines.append("")

        return "\n".join(lines)

    def to_json(self) -> str:
        """Generate a JSON report."""
        data = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": [
                {
                    "file_path": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "col_start": f.col_start,
                    "col_end": f.col_end,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "suggestion": f.suggestion,
                    "rule_id": f.rule_id,
                    "agent_id": f.agent_id,
                }
                for f in self.findings
            ],
        }
        return json.dumps(data, indent=2, ensure_ascii=False)

    def to_sarif(self, tool_name: str = "CodeGuardian") -> str:
        """Generate a SARIF 2.1.0 compliant report."""
        results = []
        for f in self.findings:
            region = {
                "startLine": f.line_start,
                "endLine": f.line_end,
            }
            if f.col_start is not None:
                region["startColumn"] = f.col_start
            if f.col_end is not None:
                region["endColumn"] = f.col_end

            results.append({
                "ruleId": f.rule_id or f.title.replace(" ", "-").lower(),
                "level": self._sarif_level(f.severity),
                "message": {"text": f.description or f.title},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.file_path},
                        "region": region,
                    }
                }],
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": tool_name}},
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2, ensure_ascii=False)

    def write(self, path: Path, format: str) -> Path:
        """Write report to a file in the specified format."""
        formatters = {
            "markdown": self.to_markdown,
            "json": self.to_json,
            "sarif": self.to_sarif,
        }
        if format not in formatters:
            raise ValueError(f"Unknown format: {format}")

        content = formatters[format]()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def _severity_table(self) -> str:
        """Build a markdown table of severity counts."""
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        rows = [
            "| Severity | Count |",
            "|----------|-------|",
        ]
        for sev, count in counts.items():
            if count > 0:
                rows.append(f"| {sev.value.capitalize()} | {count} |")
        return "\n".join(rows)

    def _group_by_file(self) -> dict[str, list[Finding]]:
        groups: dict[str, list[Finding]] = {}
        for f in self.findings:
            groups.setdefault(f.file_path, []).append(f)
        return groups

    @staticmethod
    def _sarif_level(severity: Severity) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.WARNING: "warning",
            Severity.SUGGESTION: "note",
            Severity.INFO: "none",
        }
        return mapping.get(severity, "warning")
