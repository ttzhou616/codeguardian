"""Performance analyzer agent — N+1 queries, loop inefficiencies, anti-patterns."""

from __future__ import annotations

import ast
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import RuleEngine, SKIP_EXTENSIONS
from codeguardian.scanner.rules import SecurityRule, load_performance_rules


class PerformanceAnalyzerAgent(BaseAgent):
    """Detects performance anti-patterns in Python (AST) and JS/TS/Java (regex)."""

    topic = "performance_analyzer"

    def __init__(self, name="performance_analyzer", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)

    async def setup(self) -> None:
        rules = load_performance_rules()
        pattern_rules = [r for r in rules if r.patterns]
        self.engine = RuleEngine(pattern_rules, default_category=FindingCategory.PERFORMANCE)
        await self.log("info", f"Performance analyzer loaded {len(rules)} rules "
                              f"({len(pattern_rules)} regex, Python AST for loops)")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        if not hasattr(self, "engine") or self.engine is None:
            await self.setup()

        files = scope.file_paths
        if not files:
            return []

        await self.log("info", f"Analyzing performance on {len(files)} file(s)")

        findings: list[Finding] = []

        for fp in files:
            path = Path(fp)
            ext = path.suffix.lower()
            if ext in SKIP_EXTENSIONS or not path.exists():
                continue

            if ext == ".py":
                findings.extend(self._analyze_python(fp))
            else:
                findings.extend(self.engine.scan_file(fp))

        for f in findings:
            f.category = FindingCategory.PERFORMANCE

        await self.log("info", f"Found {len(findings)} performance issue(s)")
        return findings

    def _analyze_python(self, file_path: str) -> list[Finding]:
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            return []

        findings: list[Finding] = []

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                findings.extend(self._check_python_function(node, file_path))

        return findings

    def _check_python_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, file_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        # PA-001: N+1 query — loop containing a DB call
        findings.extend(self._check_n_plus_one(node, file_path))

        # PA-002: list.append in loop instead of comprehension
        findings.extend(self._check_append_in_loop(node, file_path))

        # PA-003: string += in loop
        findings.extend(self._check_string_concat_in_loop(node, file_path))

        # PA-004: repeated attribute access in loop
        findings.extend(self._check_repeated_attr_in_loop(node, file_path))

        # PA-005: range(len(...))
        findings.extend(self._check_range_len(node, file_path))

        return findings

    # ── PA-001: N+1 query ─────────────────────────────────────────

    def _check_n_plus_one(
        self, node: ast.FunctionDef, file_path: str,
    ) -> list[Finding]:
        """Detect database queries inside for loops."""
        findings: list[Finding] = []

        db_methods = {"execute", "fetchone", "fetchall", "fetchmany", "query",
                       "find", "find_one", "findOne", "get", "save", "insert",
                       "update", "delete", "create", "filter", "all", "first"}

        for loop in ast.walk(node):
            if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
                continue

            for child in ast.walk(loop):
                if isinstance(child, ast.Call):
                    func = self._get_call_name(child)
                    if func and func.split(".")[-1] in db_methods:
                        loop_line = getattr(loop, 'lineno', 0)
                        findings.append(Finding(
                            file_path=file_path,
                            line_start=loop_line,
                            line_end=getattr(loop, 'end_lineno', loop_line),
                            title=f"Potential N+1 query: '{func}()' inside loop in '{node.name}'",
                            description="Database query executed inside a loop — each "
                                        "iteration triggers a separate query.",
                            severity=Severity.WARNING,
                            category=FindingCategory.PERFORMANCE,
                            suggestion="Batch the query or use eager loading (e.g., "
                                       "SELECT ... WHERE id IN (...)).",
                            rule_id="PA-001",
                        ))
                        break  # One finding per loop is enough

        return findings

    # ── PA-002: list.append in loop ───────────────────────────────

    def _check_append_in_loop(
        self, node: ast.FunctionDef, file_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for loop in ast.walk(node):
            if not isinstance(loop, (ast.For, ast.AsyncFor)):
                continue

            for child in ast.walk(loop):
                if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                    if child.func.attr == "append":
                        loop_line = getattr(loop, 'lineno', 0)
                        findings.append(Finding(
                            file_path=file_path,
                            line_start=child.lineno,
                            line_end=child.lineno,
                            title=f"list.append() in loop in '{node.name}'",
                            description="Using list.append() inside a for-loop; "
                                        "a list comprehension would be faster.",
                            severity=Severity.SUGGESTION,
                            category=FindingCategory.PERFORMANCE,
                            suggestion="Replace with a list comprehension: "
                                       "[expr for item in iterable].",
                            rule_id="PA-002",
                        ))
                        break  # One per loop

        return findings

    # ── PA-003: string += in loop ─────────────────────────────────

    def _check_string_concat_in_loop(
        self, node: ast.FunctionDef, file_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for loop in ast.walk(node):
            if not isinstance(loop, (ast.For, ast.AsyncFor, ast.While)):
                continue

            for child in ast.walk(loop):
                if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                    if isinstance(child.target, ast.Name):
                        findings.append(Finding(
                            file_path=file_path,
                            line_start=child.lineno,
                            line_end=child.lineno,
                            title=f"String concatenation in loop in '{node.name}'",
                            description="Using '+=' to build a string inside a loop "
                                        "creates a new string each iteration.",
                            severity=Severity.WARNING,
                            category=FindingCategory.PERFORMANCE,
                            suggestion="Use ''.join(list_of_strings) or io.StringIO for "
                                       "efficient string building.",
                            rule_id="PA-003",
                        ))
                        break  # One per loop

        return findings

    # ── PA-004: repeated attr access in loop ──────────────────────

    def _check_repeated_attr_in_loop(
        self, node: ast.FunctionDef, file_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for loop in ast.walk(node):
            if not isinstance(loop, (ast.For, ast.AsyncFor)):
                continue

            # Count attribute access chains that could be hoisted
            attr_chains: dict[str, list[int]] = {}
            for child in ast.walk(loop):
                if isinstance(child, ast.Attribute):
                    chain = self._attr_chain(child)
                    if len(chain.split(".")) >= 2:
                        attr_chains.setdefault(chain, []).append(child.lineno)

            for chain, lines in attr_chains.items():
                if len(lines) >= 3:
                    findings.append(Finding(
                        file_path=file_path,
                        line_start=lines[0],
                        line_end=lines[-1],
                        title=f"Repeated attribute access '{chain}' in loop in '{node.name}'",
                        description=f"'{chain}' accessed {len(lines)} times inside a loop.",
                        severity=Severity.SUGGESTION,
                        category=FindingCategory.PERFORMANCE,
                        suggestion=f"Hoist '{chain}' to a local variable before the loop.",
                        rule_id="PA-004",
                    ))
                    break

        return findings

    # ── PA-005: range(len(...)) ───────────────────────────────────

    def _check_range_len(
        self, node: ast.FunctionDef, file_path: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if child.func.id == "range" and child.args:
                    arg0 = child.args[0]
                    if isinstance(arg0, ast.Call) and isinstance(arg0.func, ast.Name):
                        if arg0.func.id == "len":
                            findings.append(Finding(
                                file_path=file_path,
                                line_start=child.lineno,
                                line_end=child.lineno,
                                title=f"range(len(...)) anti-pattern in '{node.name}'",
                                description="Using range(len(seq)) is slower and less "
                                            "Pythonic than enumerate().",
                                severity=Severity.SUGGESTION,
                                category=FindingCategory.PERFORMANCE,
                                suggestion="Use 'for i, item in enumerate(seq):' instead.",
                                rule_id="PA-005",
                            ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            prefix = PerformanceAnalyzerAgent._get_call_name_prefix(node.func.value)
            return f"{prefix}.{node.func.attr}" if prefix else node.func.attr
        return None

    @staticmethod
    def _get_call_name_prefix(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            inner = PerformanceAnalyzerAgent._get_call_name_prefix(node.value)
            return f"{inner}.{node.attr}" if inner else node.attr
        if isinstance(node, ast.Call):
            return PerformanceAnalyzerAgent._get_call_name(node)
        return None

    @staticmethod
    def _attr_chain(node: ast.Attribute) -> str:
        parts: list[str] = []
        current: ast.expr = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
