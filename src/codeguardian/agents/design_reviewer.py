"""Design reviewer agent — SOLID violations, coupling, architecture patterns."""

from __future__ import annotations

import ast
from collections import defaultdict
from pathlib import Path

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding, FindingCategory, Severity
from codeguardian.scanner.engine import SKIP_EXTENSIONS


class DesignReviewerAgent(BaseAgent):
    """Analyzes design quality: god classes, deep inheritance, high coupling, circular imports."""

    topic = "design_reviewer"

    def __init__(self, name="design_reviewer", config=None, bus=None):
        super().__init__(name=name, config=config, bus=bus)

    async def setup(self) -> None:
        await self.log("info", "Design reviewer ready")

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        files = [f for f in scope.file_paths if f.endswith(".py")]
        if not files:
            return []

        await self.log("info", f"Analyzing design of {len(files)} file(s)")

        findings: list[Finding] = []

        # Parse all files first
        parsed: dict[str, ast.Module] = {}
        for fp in files:
            try:
                source = Path(fp).read_text(encoding="utf-8", errors="replace")
                parsed[fp] = ast.parse(source, filename=fp)
            except Exception:
                continue

        # DR-001: Circular imports
        findings.extend(self._check_circular_imports(files, parsed))

        # DR-002: God classes (too many methods)
        for fp, tree in parsed.items():
            findings.extend(self._check_god_class(fp, tree))

        # DR-003: High coupling (too many imports)
        for fp, tree in parsed.items():
            findings.extend(self._check_high_coupling(fp, tree))

        # DR-004: Deep inheritance
        for fp, tree in parsed.items():
            findings.extend(self._check_deep_inheritance(fp, tree, parsed))

        # DR-005: Large abstract base class
        for fp, tree in parsed.items():
            findings.extend(self._check_large_abstract_class(fp, tree))

        for f in findings:
            f.category = FindingCategory.DESIGN

        await self.log("info", f"Found {len(findings)} design issue(s)")
        return findings

    # ── DR-001: Circular imports ──────────────────────────────────

    def _check_circular_imports(
        self, files: list[str], parsed: dict[str, ast.Module],
    ) -> list[Finding]:
        """Detect circular import relationships between files."""
        findings: list[Finding] = []

        imports: dict[str, set[str]] = {}
        for fp, tree in parsed.items():
            module_name = Path(fp).stem
            imported = self._get_imports(tree)
            # Map imported modules to file paths in the change scope
            resolved = set()
            for imp in imported:
                for other_fp in files:
                    if Path(other_fp).stem == imp:
                        resolved.add(other_fp)
            imports[fp] = resolved

        # Check for cycles
        for fp_a in files:
            for fp_b in imports.get(fp_a, set()):
                if fp_a in imports.get(fp_b, set()):
                    findings.append(Finding(
                        file_path=fp_a,
                        line_start=1, line_end=1,
                        title=f"Circular import between '{Path(fp_a).stem}' and '{Path(fp_b).stem}'",
                        description="Two modules import each other, creating a circular dependency.",
                        severity=Severity.WARNING,
                        category=FindingCategory.DESIGN,
                        suggestion="Extract shared dependencies into a third module, "
                                   "or use dependency inversion.",
                        rule_id="DR-001",
                    ))

        return findings

    # ── DR-002: God class ─────────────────────────────────────────

    def _check_god_class(self, file_path: str, tree: ast.Module) -> list[Finding]:
        """Detect classes with too many methods (>15)."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            methods = [
                n for n in ast.walk(node)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if len(methods) > 15:
                findings.append(Finding(
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    title=f"God class: '{node.name}' has {len(methods)} methods",
                    description=f"Class has {len(methods)} methods (max recommended: 15). "
                                "This violates the Single Responsibility Principle.",
                    severity=Severity.WARNING,
                    category=FindingCategory.DESIGN,
                    suggestion="Split the class into smaller, focused classes each "
                               "with a single responsibility.",
                    rule_id="DR-002",
                ))

        return findings

    # ── DR-003: High coupling ────────────────────────────────────

    def _check_high_coupling(
        self, file_path: str, tree: ast.Module,
    ) -> list[Finding]:
        """Detect modules with too many imports (>12)."""
        imports = self._get_imports(tree)
        if len(imports) > 12:
            return [Finding(
                file_path=file_path,
                line_start=1, line_end=1,
                title=f"High coupling: {len(imports)} imports in '{Path(file_path).stem}'",
                description=f"Module imports from {len(imports)} different modules "
                            "(max recommended: 12).",
                severity=Severity.SUGGESTION,
                category=FindingCategory.DESIGN,
                suggestion="Consider splitting the module or using facade patterns "
                           "to reduce direct dependencies.",
                rule_id="DR-003",
            )]
        return []

    # ── DR-004: Deep inheritance ─────────────────────────────────

    def _check_deep_inheritance(
        self, file_path: str, tree: ast.Module, parsed: dict[str, ast.Module],
    ) -> list[Finding]:
        """Detect class inheritance chains deeper than 3 levels."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            depth = self._inheritance_depth(node, parsed)
            if depth > 3:
                findings.append(Finding(
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.lineno,
                    title=f"Deep inheritance: '{node.name}' has {depth} levels",
                    description=f"Inheritance depth of {depth} exceeds the "
                                "recommended maximum of 3.",
                    severity=Severity.SUGGESTION,
                    category=FindingCategory.DESIGN,
                    suggestion="Prefer composition over inheritance. Use mixins "
                               "or dependency injection instead of deep class hierarchies.",
                    rule_id="DR-004",
                ))

        return findings

    # ── DR-005: Large abstract class ──────────────────────────────

    def _check_large_abstract_class(
        self, file_path: str, tree: ast.Module,
    ) -> list[Finding]:
        """Detect abstract classes with too many abstract methods (>6)."""
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue

            abstract_methods = [
                n for n in ast.walk(node)
                if isinstance(n, ast.FunctionDef)
                and (self._has_decorator(n, "abstractmethod")
                     or self._is_stub_method(n))
            ]

            if len(abstract_methods) > 6:
                findings.append(Finding(
                    file_path=file_path,
                    line_start=node.lineno,
                    line_end=node.end_lineno or node.lineno,
                    title=f"Large abstract class: '{node.name}' has "
                          f"{len(abstract_methods)} abstract methods",
                    description="Too many abstract methods suggest the interface "
                                "should be split (Interface Segregation Principle).",
                    severity=Severity.SUGGESTION,
                    category=FindingCategory.DESIGN,
                    suggestion="Split into smaller, focused interfaces/abstract classes.",
                    rule_id="DR-005",
                ))

        return findings

    # ── Helpers ───────────────────────────────────────────────────

    @staticmethod
    def _get_imports(tree: ast.Module) -> set[str]:
        """Extract imported module names from an AST."""
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    names.add(node.module.split(".")[0])
        return names

    @staticmethod
    def _inheritance_depth(
        class_node: ast.ClassDef, parsed: dict[str, ast.Module], depth: int = 1,
    ) -> int:
        """Calculate inheritance chain depth for a class."""
        if depth > 10:
            return depth  # Safety limit

        max_parent_depth = depth
        for base in class_node.bases:
            if isinstance(base, ast.Name):
                # Look for parent class definition in parsed modules
                for _fp, tree in parsed.items():
                    for node in ast.walk(tree):
                        if isinstance(node, ast.ClassDef) and node.name == base.id:
                            parent_depth = DesignReviewerAgent._inheritance_depth(
                                node, parsed, depth + 1,
                            )
                            max_parent_depth = max(max_parent_depth, parent_depth)
        return max_parent_depth

    @staticmethod
    def _has_decorator(func: ast.FunctionDef, name: str) -> bool:
        return any(
            (isinstance(d, ast.Name) and d.id == name)
            or (isinstance(d, ast.Attribute) and d.attr == name)
            for d in func.decorator_list
        )

    @staticmethod
    def _is_stub_method(func: ast.FunctionDef) -> bool:
        """Check if a method body is just 'pass' or '...' or a docstring."""
        body = func.body
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            return True
        if len(body) == 1 and isinstance(body[0], ast.Expr):
            val = body[0].value
            if isinstance(val, ast.Constant) and val.value is ...:
                return True
        return False
