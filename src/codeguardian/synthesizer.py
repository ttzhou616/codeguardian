"""Synthesizer — deduplicate, prioritize, and correlate findings."""

from __future__ import annotations

from collections import defaultdict

from codeguardian.models.findings import Finding, Severity


class Synthesizer:
    """Merges raw agent findings into a clean, prioritized result set."""

    SEVERITY_WEIGHT = {
        Severity.CRITICAL: 25,
        Severity.WARNING: 10,
        Severity.SUGGESTION: 3,
        Severity.INFO: 1,
    }

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Merge findings with identical signatures, keeping the most severe."""
        seen: dict[str, Finding] = {}
        for f in findings:
            sig = f.signature
            if sig in seen:
                # Keep the finding from the more specific agent (higher severity wins)
                existing = seen[sig]
                if self.SEVERITY_WEIGHT[f.severity] > self.SEVERITY_WEIGHT[existing.severity]:
                    seen[sig] = f
            else:
                seen[sig] = f
        return list(seen.values())

    def prioritize(self, findings: list[Finding]) -> list[Finding]:
        """Sort findings by severity (descending), then by file path."""
        return sorted(
            findings,
            key=lambda f: (self.SEVERITY_WEIGHT[f.severity], f.file_path),
            reverse=True,
        )

    def correlate(self, findings: list[Finding]) -> list[Finding]:
        """Identify findings that may be related to each other.

        Phase 2: cross-reference interface changes with dependents,
        detect cascading issues, etc. For now this is a pass-through.
        """
        return findings

    def calculate_risk_score(self, findings: list[Finding]) -> float:
        """Compute a 0–100 risk score based on finding severity distribution."""
        if not findings:
            return 0.0
        total = sum(self.SEVERITY_WEIGHT[f.severity] for f in findings)
        # Normalize: assume 100 is "very high risk"
        normalized = min(total / 2, 100.0)
        return round(normalized, 1)

    def calculate_review_score(self, findings: list[Finding]) -> float:
        """Compute a 100–0 review score. Starts at 100, deductions per finding."""
        deductions = sum(
            self.SEVERITY_WEIGHT[f.severity] / 2 for f in findings
        )
        return max(100.0 - round(deductions, 1), 0.0)

    def process(self, findings: list[Finding]) -> list[Finding]:
        """Full pipeline: deduplicate → correlate → prioritize."""
        unique = self.deduplicate(findings)
        correlated = self.correlate(unique)
        return self.prioritize(correlated)
