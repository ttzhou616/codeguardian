"""Knowledge base for false positive tracking and team rules."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from codeguardian.models.findings import Finding


class KnowledgeBase:
    """Stores team-specific knowledge: false positives, custom rules, ADRs.

    Phase 3 will replace this in-memory store with a vector database (Chroma/Qdrant).
    """

    def __init__(self, storage_path: Optional[Path] = None):
        self._false_positives: set[str] = set()
        self._team_rules: list[dict] = []
        self._storage_path = storage_path or Path(".codeguardian_kb")

    def add_false_positive(self, finding_signature: str) -> None:
        """Record a false positive signature so it's filtered in future runs."""
        self._false_positives.add(finding_signature)

    def is_false_positive(self, finding: Finding) -> bool:
        """Check if a finding matches a known false positive."""
        return finding.signature in self._false_positives

    def remove_false_positive(self, finding_signature: str) -> None:
        """Remove a false positive entry (undo)."""
        self._false_positives.discard(finding_signature)

    def filter_false_positives(self, findings: list[Finding]) -> list[Finding]:
        """Return findings with known false positives removed."""
        return [f for f in findings if not self.is_false_positive(f)]

    def add_team_rule(self, rule: dict) -> None:
        """Add a custom team rule."""
        self._team_rules.append(rule)

    def get_team_rules(self) -> list[dict]:
        """Return all stored team rules."""
        return list(self._team_rules)
