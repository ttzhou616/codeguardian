"""Rule execution engine — scans files against security rules."""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from codeguardian.models.findings import Finding, FindingCategory
from codeguardian.scanner.rules import SecurityRule

# Extensions to skip (non-text files)
SKIP_EXTENSIONS = {
    ".pyc", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv",
    ".woff", ".woff2", ".ttf", ".eot",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".min.js", ".min.css",
}


class RuleEngine:
    """Applies scan rules to source files."""

    def __init__(self, rules: list[SecurityRule], default_category: FindingCategory = FindingCategory.SECURITY):
        self._rules = rules
        self._default_category = default_category
        self._compiled: dict[str, list[re.Pattern]] = {}
        for rule in rules:
            if rule.patterns:
                self._compiled[rule.rule_id] = [re.compile(p) for p in rule.patterns]

    @property
    def rules(self) -> list[SecurityRule]:
        return list(self._rules)

    def rules_for_file(self, file_path: str) -> list[SecurityRule]:
        """Return rules applicable to a given file based on its extension."""
        ext = Path(file_path).suffix.lower()
        return [
            r for r in self._rules
            if not r.file_extensions or ext in r.file_extensions
        ]

    def scan_file(self, file_path: str) -> list[Finding]:
        """Scan a single file and return findings."""
        path = Path(file_path)
        ext = path.suffix.lower()

        if ext in SKIP_EXTENSIONS or not path.exists():
            return []

        try:
            lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
        except Exception:
            return []

        applicable = self.rules_for_file(file_path)
        if not applicable:
            return []

        findings: list[Finding] = []

        for rule in applicable:
            compiled = self._compiled[rule.rule_id]
            for i, line in enumerate(lines, start=1):
                # Skip comment lines to reduce false positives
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("/*"):
                    # But still check for secrets which might be in comments
                    if rule.category != "secrets":
                        continue

                for pat in compiled:
                    match = pat.search(line)
                    if match:
                        findings.append(Finding(
                            file_path=file_path,
                            line_start=i,
                            line_end=i,
                            col_start=match.start(),
                            col_end=match.end(),
                            title=rule.title,
                            description=rule.description,
                            severity=rule.severity,
                            category=self._default_category,
                            suggestion=rule.suggestion,
                            rule_id=rule.rule_id,
                        ))
                        # One finding per rule per line is enough
                        break

        return findings

    async def scan_files(self, file_paths: list[str]) -> list[Finding]:
        """Scan multiple files concurrently."""
        if not file_paths:
            return []

        loop = asyncio.get_running_loop()
        tasks = [
            loop.run_in_executor(None, self.scan_file, fp)
            for fp in file_paths
        ]
        results = await asyncio.gather(*tasks)
        all_findings: list[Finding] = []
        for findings in results:
            all_findings.extend(findings)
        return all_findings
