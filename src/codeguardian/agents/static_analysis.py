"""Static analysis agent — complexity, dead code, type safety, structure."""

from __future__ import annotations

import ast
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import RuleEngine, SKIP_EXTENSIONS
from codeguardian.scanner.rules import SecurityRule, load_static_rules


class StaticAnalysisAgent(BaseAgent):
    """Analyzes code structure: complexity, nesting depth, parameter count, etc."""

    topic = "static_analysis"

    def __init__(self, name="static_analysis", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)

    async def setup(self) -> None:
        rules = load_static_rules()
        pattern_rules = [r for r in rules if r.patterns]
        self.engine = RuleEngine(pattern_rules, default_category=FindingCategory.STATIC)
        await self.log("info", f"Static analysis loaded {len(rules)} rules "
                              f"({len(pattern_rules)} pattern, Python AST for complexity)")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        if not hasattr(self, "engine") or self.engine is None:
            await self.setup()

        files = scope.file_paths
        if not files:
            return []

        await self.log("info", f"Analyzing {len(files)} file(s)")

        findings: list[Finding] = []

        for fp in files:
            path = Path(fp)
            ext = path.suffix.lower()
            if ext in SKIP_EXTENSIONS or not path.exists():
                continue

            if ext == ".py":
                findings.extend(self._analyze_python(fp))
            else:
                # Regex-based rules for other languages
                findings.extend(self.engine.scan_file(fp))

        # Set category for all findings
        for f in findings:
            f.category = FindingCategory.STATIC

        await self.log("info", f"Found {len(findings)} static analysis issue(s)")
        return findings

    def _analyze_python(self, file_path: str) -> list[Finding]:
        """Deep AST-based analysis for Python files."""
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

        # SA-001: Cyclomatic complexity
        complexity = self._cyclomatic_complexity(node)
        if complexity > 10:
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                title=f"High cyclomatic complexity ({complexity}) in '{node.name}'",
                description=f"Cyclomatic complexity of {complexity} exceeds the threshold of 10.",
                severity=Severity.WARNING,
                category=FindingCategory.STATIC,
                suggestion="Refactor into smaller functions or simplify branching logic.",
                rule_id="SA-001",
            ))

        # SA-002: Too many parameters (>5)
        param_count = len(node.args.args)
        if param_count > 5:
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.lineno,
                title=f"Too many parameters ({param_count}) in '{node.name}'",
                description=f"Function has {param_count} parameters (max recommended: 5).",
                severity=Severity.SUGGESTION,
                category=FindingCategory.STATIC,
                suggestion="Group parameters into a dataclass, TypedDict, or configuration object.",
                rule_id="SA-002",
            ))

        # SA-003: Deep nesting (>4 levels)
        max_depth = self._max_nesting_depth(node)
        if max_depth > 4:
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                title=f"Deep nesting ({max_depth} levels) in '{node.name}'",
                description=f"Maximum nesting depth of {max_depth} exceeds the threshold of 4.",
                severity=Severity.WARNING,
                category=FindingCategory.STATIC,
                suggestion="Extract nested blocks into separate functions or use early returns.",
                rule_id="SA-003",
            ))

        # SA-004: Bare except clause
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                if child.type is None:
                    findings.append(Finding(
                        file_path=file_path,
                        line_start=child.lineno,
                        line_end=child.lineno,
                        title=f"Bare except clause in '{node.name}'",
                        description="A bare 'except:' catches all exceptions including SystemExit and KeyboardInterrupt.",
                        severity=Severity.WARNING,
                        category=FindingCategory.STATIC,
                        suggestion="Catch specific exceptions (e.g., 'except ValueError as e').",
                        rule_id="SA-004",
                    ))

        # SA-005: Too many return statements (>4)
        return_count = self._count_returns(node)
        if return_count > 4:
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                title=f"Too many return statements ({return_count}) in '{node.name}'",
                description=f"Function has {return_count} return statements (max recommended: 4).",
                severity=Severity.SUGGESTION,
                category=FindingCategory.STATIC,
                suggestion="Consolidate return paths or use early returns for guard clauses only.",
                rule_id="SA-005",
            ))

        # SA-006: Too many local variables (>10)
        local_count = self._count_locals(node)
        if local_count > 10:
            findings.append(Finding(
                file_path=file_path,
                line_start=node.lineno,
                line_end=node.end_lineno or node.lineno,
                title=f"Too many local variables ({local_count}) in '{node.name}'",
                description=f"Function has {local_count} local variables (max recommended: 10).",
                severity=Severity.SUGGESTION,
                category=FindingCategory.STATIC,
                suggestion="Extract related variables into a separate class or function.",
                rule_id="SA-006",
            ))

        return findings

    # ── AST analysis helpers ──────────────────────────────────────

    @staticmethod
    def _cyclomatic_complexity(node: ast.AST) -> int:
        """McCabe cyclomatic complexity: 1 + number of decision points."""
        count = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                  ast.ExceptHandler, ast.With, ast.AsyncWith)):
                count += 1
            elif isinstance(child, ast.BoolOp):
                count += len(child.values) - 1
        return count

    @staticmethod
    def _max_nesting_depth(node: ast.AST) -> int:
        """Find the maximum nesting depth in this AST node."""

        def _depth(n: ast.AST, current: int) -> int:
            max_d = current
            for child in ast.iter_child_nodes(n):
                if isinstance(child, (ast.If, ast.For, ast.AsyncFor, ast.While,
                                       ast.With, ast.AsyncWith, ast.Try,
                                       ast.ExceptHandler)):
                    d = _depth(child, current + 1)
                else:
                    d = _depth(child, current)
                max_d = max(max_d, d)
            return max_d

        return _depth(node, 0)

    @staticmethod
    def _count_returns(node: ast.AST) -> int:
        return sum(1 for _ in ast.walk(node) if isinstance(_, ast.Return))

    @staticmethod
    def _count_locals(node: ast.FunctionDef) -> int:
        """Count distinct local variable names assigned in the function body."""
        names: set[str] = set()
        for child in ast.walk(node):
            # Direct name assignments (x = ...)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
                names.add(child.id)
            # Assignment targets (x, y = ...)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        names.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for t in target.elts:
                            if isinstance(t, ast.Name):
                                names.add(t.id)
        return len(names)
