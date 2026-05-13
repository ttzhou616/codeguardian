"""Core data models for CodeGuardian."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    SUGGESTION = "suggestion"
    INFO = "info"


class FindingCategory(Enum):
    SECURITY = "security"
    PERFORMANCE = "performance"
    DESIGN = "design"
    STYLE = "style"
    TEST = "test"
    STATIC = "static"


class ReportFormat(Enum):
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"


@dataclass
class Finding:
    """A single issue discovered during review."""

    file_path: str
    line_start: int
    line_end: int
    col_start: Optional[int] = None
    col_end: Optional[int] = None
    title: str = ""
    description: str = ""
    severity: Severity = Severity.WARNING
    category: FindingCategory = FindingCategory.STATIC
    suggestion: Optional[str] = None
    rule_id: Optional[str] = None
    agent_id: Optional[str] = None

    @property
    def signature(self) -> str:
        """Stable key for deduplication."""
        return f"{self.file_path}:{self.line_start}:{self.rule_id or self.title}"


@dataclass
class ChangedFile:
    path: str
    status: str  # added, modified, deleted, renamed
    additions: int = 0
    deletions: int = 0
    language: Optional[str] = None


@dataclass
class ChangeScope:
    """Describes the scope of code changes under review."""

    changed_files: list[ChangedFile] = field(default_factory=list)
    diff_text: Optional[str] = None
    base_ref: Optional[str] = None
    head_ref: Optional[str] = None

    @property
    def file_paths(self) -> list[str]:
        return [f.path for f in self.changed_files]


@dataclass
class ReviewReport:
    """Aggregated review results."""

    change_scope: ChangeScope = field(default_factory=ChangeScope)
    findings: list[Finding] = field(default_factory=list)
    risk_score: float = 0.0  # 0–100
    review_score: float = 100.0  # 100–0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def suggestion_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.SUGGESTION)
