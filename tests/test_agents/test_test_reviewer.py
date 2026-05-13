"""Tests for the TestReviewerAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.test_reviewer import TestReviewerAgent
from codeguardian.models.findings import ChangeScope, ChangedFile, FindingCategory


def _make_scope(files: list[Path]) -> ChangeScope:
    return ChangeScope(
        changed_files=[
            ChangedFile(path=str(f.resolve()), status="modified", language=f.suffix.lstrip("."))
            for f in files
        ]
    )


# ── TR-001: Missing test file ────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_missing_test_file():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "calculator.py"
        src.write_text("def add(a, b):\n    return a + b\n")
        findings = await agent.analyze(_make_scope([src]))
        assert any(f.rule_id == "TR-001" for f in findings)


@pytest.mark.asyncio
async def test_no_warning_when_test_exists():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "calculator.py"
        test = Path(td) / "test_calculator.py"
        src.write_text("def add(a, b):\n    return a + b\n")
        test.write_text("def test_add():\n    assert add(1,2) == 3\n")
        findings = await agent.analyze(_make_scope([src, test]))
        assert not any(f.rule_id == "TR-001" for f in findings)


# ── TR-002: Untested function ────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_untested_function():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "mathops.py"
        test = Path(td) / "test_mathops.py"
        src.write_text("""
def add(a, b):
    return a + b

def subtract(a, b):
    return a - b
""")
        # test_add exists but test_subtract is missing
        test.write_text("""
def test_add():
    assert add(1, 2) == 3
""")
        findings = await agent.analyze(_make_scope([src, test]))
        tr002 = [f for f in findings if f.rule_id == "TR-002"]
        assert len(tr002) >= 1
        assert any("subtract" in f.title for f in tr002)


@pytest.mark.asyncio
async def test_no_warning_for_tested_functions():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "mathops.py"
        test = Path(td) / "test_mathops.py"
        src.write_text("def add(a, b):\n    return a + b\n")
        test.write_text("def test_add():\n    assert add(1,2) == 3\n")
        findings = await agent.analyze(_make_scope([src, test]))
        assert not any(f.rule_id == "TR-002" for f in findings)


# ── TR-003: No assertions in test ────────────────────────────────

@pytest.mark.asyncio
async def test_detects_missing_assertions():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        test = Path(td) / "test_empty.py"
        test.write_text("""
def test_something():
    result = do_thing()
    print(result)
""")
        findings = await agent.analyze(_make_scope([test]))
        assert any(f.rule_id == "TR-003" for f in findings)


@pytest.mark.asyncio
async def test_no_warning_when_assertions_exist():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        test = Path(td) / "test_good.py"
        test.write_text("""
def test_add():
    assert add(1, 2) == 3
""")
        findings = await agent.analyze(_make_scope([test]))
        assert not any(f.rule_id == "TR-003" for f in findings)


# ── TR-004: Low coverage ratio ───────────────────────────────────

@pytest.mark.asyncio
async def test_detects_low_coverage_ratio():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "service.py"
        test = Path(td) / "test_service.py"
        src.write_text("""
def create():
    pass
def read():
    pass
def update():
    pass
def delete():
    pass
""")
        test.write_text("""
def test_create():
    assert True
""")
        findings = await agent.analyze(_make_scope([src, test]))
        assert any(f.rule_id == "TR-004" for f in findings)


@pytest.mark.asyncio
async def test_no_warning_for_good_coverage():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "simple.py"
        test = Path(td) / "test_simple.py"
        src.write_text("def add(a, b):\n    return a + b\n")
        test.write_text("def test_add():\n    assert add(1,2) == 3\n")
        findings = await agent.analyze(_make_scope([src, test]))
        assert not any(f.rule_id == "TR-004" for f in findings)


# ── Category ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_have_test_category():
    agent = TestReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        src = Path(td) / "nope.py"
        src.write_text("def nope():\n    pass\n")
        findings = await agent.analyze(_make_scope([src]))
        for f in findings:
            assert f.category == FindingCategory.TEST
