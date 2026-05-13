"""Tests for the StaticAnalysisAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.static_analysis import StaticAnalysisAgent
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


# ── Cyclomatic Complexity ────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_high_complexity():
    agent = StaticAnalysisAgent()
    # 12 decision points → complexity = 13
    code = "def complex_func(x):\n"
    for i in range(12):
        code += f"    if x == {i}:\n        return {i}\n"
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-001" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_low_complexity():
    agent = StaticAnalysisAgent()
    f = _write_temp("def simple(x):\n    return x + 1\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "SA-001" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Too Many Parameters ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_too_many_params():
    agent = StaticAnalysisAgent()
    params = ", ".join(f"p{i}" for i in range(7))
    f = _write_temp(f"def many_params({params}):\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-002" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_few_params():
    agent = StaticAnalysisAgent()
    f = _write_temp("def few_params(a, b, c):\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "SA-002" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Deep Nesting ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_deep_nesting():
    agent = StaticAnalysisAgent()
    code = """def deep():
    if True:
        for i in range(1):
            while False:
                with open('x') as f:
                    if f:
                        pass
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-003" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_shallow_nesting():
    agent = StaticAnalysisAgent()
    f = _write_temp("def shallow():\n    if True:\n        pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "SA-003" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Bare Except ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_bare_except():
    agent = StaticAnalysisAgent()
    f = _write_temp("""
def bad():
    try:
        risky()
    except:
        pass
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-004" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_named_except():
    agent = StaticAnalysisAgent()
    f = _write_temp("""
def good():
    try:
        risky()
    except ValueError:
        pass
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "SA-004" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Too Many Returns ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_too_many_returns():
    agent = StaticAnalysisAgent()
    f = _write_temp("""
def many_returns(x):
    if x == 0: return 'a'
    if x == 1: return 'b'
    if x == 2: return 'c'
    if x == 3: return 'd'
    if x == 4: return 'e'
    return 'f'
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-005" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_few_returns():
    agent = StaticAnalysisAgent()
    f = _write_temp("def one_return(x):\n    return x * 2\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "SA-005" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Too Many Locals ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_too_many_locals():
    agent = StaticAnalysisAgent()
    lines = ["def many_locals():"]
    for i in range(12):
        lines.append(f"    v{i} = {i}")
    lines.append("    return sum([v0, v1])")
    f = _write_temp("\n".join(lines))
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-006" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Non-Python File (regex rules) ────────────────────────────────

@pytest.mark.asyncio
async def test_detects_console_log_in_js():
    agent = StaticAnalysisAgent()
    f = _write_temp("console.log('debug');\n", suffix=".js")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-010" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_var_in_js():
    agent = StaticAnalysisAgent()
    f = _write_temp("var x = 1;\n", suffix=".js")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "SA-012" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Clean Code ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_code_no_issues():
    agent = StaticAnalysisAgent()
    f = _write_temp("""
def calculate(items):
    total = 0
    for item in items:
        if item.active:
            total += item.price
        else:
            total += item.base_price
    return total
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert len(findings) == 0
    finally:
        f.unlink(missing_ok=True)


# ── Category ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_have_static_category():
    agent = StaticAnalysisAgent()
    f = _write_temp("""
def bad():
    try:
        x()
    except:
        pass
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        for finding in findings:
            assert finding.category == FindingCategory.STATIC
    finally:
        f.unlink(missing_ok=True)
