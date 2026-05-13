"""Tests for the StyleCheckerAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.style_checker import StyleCheckerAgent
from codeguardian.models.findings import ChangeScope, ChangedFile, FindingCategory


def _make_scope(files: list[Path]) -> ChangeScope:
    return ChangeScope(
        changed_files=[
            ChangedFile(path=str(f.resolve()), status="modified", language=f.suffix.lstrip("."))
            for f in files
        ]
    )


def _write_temp(content: str, suffix: str = ".py") -> Path:
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    tmp.write(content)
    tmp.close()
    return Path(tmp.name)


# ── Naming Convention ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_bad_function_name():
    """Functions with PascalCase should be flagged."""
    agent = StyleCheckerAgent()
    f = _write_temp("def BadFunctionName():\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "CG-001" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_good_function_name():
    """Functions with snake_case should pass."""
    agent = StyleCheckerAgent()
    f = _write_temp("def good_function_name():\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "CG-001" not in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_bad_class_name():
    """Classes with snake_case should be flagged."""
    agent = StyleCheckerAgent()
    f = _write_temp("class bad_class_name:\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "CG-002" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_good_class_name():
    """Classes with PascalCase should pass."""
    agent = StyleCheckerAgent()
    f = _write_temp("class GoodClassName:\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "CG-002" not in rule_ids
    finally:
        f.unlink(missing_ok=True)


# ── Function Length ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_long_function():
    """Function exceeding 50 lines should be flagged."""
    agent = StyleCheckerAgent()
    lines = ["def long_function():"]
    lines.extend([f"    x{i} = {i}" for i in range(55)])
    f = _write_temp("\n".join(lines))
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any("too long" in f.title.lower() for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_short_function():
    """Function under 50 lines should pass."""
    agent = StyleCheckerAgent()
    f = _write_temp("def short():\n    return 1\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any("too long" in f.title.lower() for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Disallowed Patterns ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_print_statement():
    """print() in Python code should be flagged."""
    agent = StyleCheckerAgent()
    f = _write_temp("print('debug info')\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "CG-004" in rule_ids
    finally:
        f.unlink(missing_ok=True)


# ── Findings Category ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_have_style_category():
    """All style findings should have category STYLE."""
    agent = StyleCheckerAgent()
    content = """def BadName():
    print("hello")
"""
    f = _write_temp(content)
    try:
        findings = await agent.analyze(_make_scope([f]))
        for finding in findings:
            assert finding.category == FindingCategory.STYLE
    finally:
        f.unlink(missing_ok=True)


# ── Clean Code ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_code_no_style_issues():
    """Well-styled code should produce no findings."""
    agent = StyleCheckerAgent()
    content = """def calculate_total(items):
    total = 0
    for item in items:
        total += item.price
    return total


class ShoppingCart:
    def add_item(self, item):
        pass
"""
    f = _write_temp(content)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert len(findings) == 0
    finally:
        f.unlink(missing_ok=True)
