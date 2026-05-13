"""Test reviewer agent — coverage gaps, missing tests, weak assertions."""

from __future__ import annotations

import ast
import re
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import SKIP_EXTENSIONS


class TestReviewerAgent(BaseAgent):
    """Checks test coverage: missing test files, untested functions, weak assertions."""

    __test__ = False
    topic = "test_reviewer"

    def __init__(self, name="test_reviewer", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)

    async def setup(self) -> None:
        self.test_patterns = [
            r"test_\w+\.py$", r"\w+_test\.py$", r"\w+\.test\.py$",
            r"test_\w+\.js$", r"\w+\.test\.js$", r"\w+\.spec\.ts$",
            r"\w+Test\.java$", r"\w+_test\.go$",
        ]
        await self.log("info", "Test reviewer ready")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        files = scope.file_paths
        if not files:
            return []

        await self.log("info", f"Reviewing tests for {len(files)} file(s)")

        findings: list[Finding] = []

        # Build project file index for test matching
        source_files = [f for f in files if self._is_source_file(f)]
        test_files = [f for f in files if self._is_test_file(f)]
        all_project_files = self._collect_project_files(source_files)

        # TR-001: Source files without corresponding tests
        for sf in source_files:
            if not self._find_test_file(sf, all_project_files):
                findings.append(Finding(
                    file_path=sf,
                    line_start=1, line_end=1,
                    title="Missing test file",
                    description=f"No corresponding test file found for '{Path(sf).name}'.",
                    severity=Severity.SUGGESTION,
                    category=FindingCategory.TEST,
                    suggestion=f"Add tests in a file like 'test_{Path(sf).stem}.py'.",
                    rule_id="TR-001",
                ))

        # TR-002: Functions without matching test functions
        for sf in source_files:
            findings.extend(self._check_untested_functions(sf, all_project_files))

        # TR-003: Test files with no assertions
        for tf in test_files:
            findings.extend(self._check_assertions(tf))

        # TR-004: Sparse test coverage (many source funcs, few test funcs)
        for sf in source_files:
            findings.extend(self._check_coverage_ratio(sf, all_project_files))

        for f in findings:
            f.category = FindingCategory.TEST

        await self.log("info", f"Found {len(findings)} test gap(s)")
        return findings

    # ── TR-001: Missing test file ──────────────────────────────────

    def _is_source_file(self, file_path: str) -> bool:
        p = Path(file_path)
        ext = p.suffix.lower()
        if ext in SKIP_EXTENSIONS:
            return False
        source_exts = {".py", ".js", ".ts", ".java", ".go", ".rs", ".rb"}
        if ext not in source_exts:
            return False
        name = p.stem
        # Exclude test files, __init__, setup files
        return not any(
            name.startswith("test_") or name.endswith("_test") or
            name.endswith(".test") or name.endswith(".spec") or
            name == "__init__" or name == "conftest" or name == "setup"
            for _ in [1]
        )

    def _is_test_file(self, file_path: str) -> bool:
        p = Path(file_path)
        name = p.stem
        return bool(
            name.startswith("test_") or name.endswith("_test") or
            name.endswith(".test") or name.endswith(".spec") or
            "Test" in name or name.endswith("_test")
        )

    def _collect_project_files(self, source_files: list[str]) -> list[str]:
        """Collect sibling project files to match tests against."""
        project_files: list[str] = []
        seen_dirs = set()
        for sf in source_files:
            parent = str(Path(sf).parent)
            if parent in seen_dirs:
                continue
            seen_dirs.add(parent)
            p = Path(parent)
            if p.exists():
                for f in p.rglob("*"):
                    if f.is_file():
                        project_files.append(str(f.resolve()))
        return list(set(project_files))

    def _find_test_file(self, source_path: str, all_files: list[str]) -> str | None:
        """Try to find a matching test file for a source file."""
        p = Path(source_path)
        stem = p.stem
        parent_dir = p.parent.name

        candidates = [
            f"{stem}_test{p.suffix}",
            f"test_{stem}{p.suffix}",
            f"{stem}.test{p.suffix}",
            f"{stem}.spec{p.suffix}",
            f"{stem}Test{p.suffix}",
        ]

        # Also check test/ or tests/ subdirectories
        for d in ["tests", "test", "__tests__"]:
            test_dir = Path(p.parent) / d
            if test_dir.exists():
                for c in candidates:
                    test_path = test_dir / c
                    if test_path.exists():
                        return str(test_path)

        # Check same directory
        for c in candidates:
            test_path = Path(p.parent) / c
            if test_path.exists():
                return str(test_path)

        # Check in collected list
        for af in all_files:
            afp = Path(af)
            if afp.stem in candidates or afp.name in candidates:
                return af

        return None

    # ── TR-002: Untested functions ─────────────────────────────────

    def _check_untested_functions(
        self, source_path: str, all_files: list[str],
    ) -> list[Finding]:
        """Check if functions in source have matching test functions."""
        if not source_path.endswith(".py"):
            return []

        try:
            source = Path(source_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except Exception:
            return []

        findings: list[Finding] = []
        funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        if not funcs:
            return []

        test_path = self._find_test_file(source_path, all_files)
        if not test_path:
            return []

        try:
            test_source = Path(test_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        for func in funcs:
            if func.name.startswith("_"):
                continue  # Private functions are optional to test
            # Look for test_<funcname> pattern in test file
            if f"test_{func.name}" not in test_source and f"test_{func.name.lower()}" not in test_source:
                findings.append(Finding(
                    file_path=source_path,
                    line_start=func.lineno,
                    line_end=func.lineno,
                    title=f"Function '{func.name}' may lack test coverage",
                    description=f"No 'test_{func.name}' found in '{Path(test_path).name}'.",
                    severity=Severity.INFO,
                    category=FindingCategory.TEST,
                    suggestion=f"Add a test function 'def test_{func.name}():' for this function.",
                    rule_id="TR-002",
                ))

        return findings

    # ── TR-003: No assertions ─────────────────────────────────────

    def _check_assertions(self, test_path: str) -> list[Finding]:
        """Check that a test file contains assertion statements."""
        findings: list[Finding] = []

        try:
            source = Path(test_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        # Common assertion patterns across languages
        assert_patterns = [
            r"\bassert\b", r"\.assert\b", r"\bassertThat\b",
            r"\bexpect\(", r"\.should\b", r"\bmust\b",
            r"\bverify\b", r"\bassertEquals\b", r"\bassertTrue\b",
        ]

        has_assertion = any(re.search(p, source) for p in assert_patterns)
        # Also check if file has test functions at all
        has_test_funcs = bool(re.search(r"def test_|def it_|it\(|test\(|@Test", source))

        if not has_test_funcs and test_path.endswith(".py"):
            return findings  # Not a real test file

        if not has_assertion:
            findings.append(Finding(
                file_path=test_path,
                line_start=1, line_end=1,
                title="Test file has no assertions",
                description=f"No assertion statements found in '{Path(test_path).name}'.",
                severity=Severity.WARNING,
                category=FindingCategory.TEST,
                suggestion="Add assertions (assert, assertEquals, expect, etc.) to verify behavior.",
                rule_id="TR-003",
            ))

        return findings

    # ── TR-004: Coverage ratio ────────────────────────────────────

    def _check_coverage_ratio(
        self, source_path: str, all_files: list[str],
    ) -> list[Finding]:
        """Check ratio of test functions to source functions."""
        if not source_path.endswith(".py"):
            return []

        try:
            source = Path(source_path).read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except Exception:
            return []

        source_funcs = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and not n.name.startswith("_")]
        if len(source_funcs) <= 1:
            return []

        test_path = self._find_test_file(source_path, all_files)
        if not test_path:
            return []

        try:
            test_source = Path(test_path).read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        test_func_count = len(re.findall(r"def test_\w+", test_source))
        if test_func_count == 0:
            return []

        if test_func_count < len(source_funcs) * 0.5:
            return [Finding(
                file_path=source_path,
                line_start=1, line_end=1,
                title="Low test coverage ratio",
                description=f"Source has {len(source_funcs)} public functions "
                            f"but test file has only {test_func_count} test functions.",
                severity=Severity.SUGGESTION,
                category=FindingCategory.TEST,
                suggestion="Add more test functions to cover all public functions.",
                rule_id="TR-004",
            )]

        return []
