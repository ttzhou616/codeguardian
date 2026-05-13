"""Tests for the DesignReviewerAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.design_reviewer import DesignReviewerAgent
from codeguardian.models.findings import ChangeScope, ChangedFile, FindingCategory


def _make_scope(files: list[Path]) -> ChangeScope:
    return ChangeScope(
        changed_files=[
            ChangedFile(path=str(f.resolve()), status="modified", language=f.suffix.lstrip("."))
            for f in files
        ]
    )


# ── DR-001: Circular imports ─────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_circular_import():
    agent = DesignReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "module_a.py"
        b = Path(td) / "module_b.py"
        a.write_text("import module_b\n\ndef func_a():\n    pass\n")
        b.write_text("import module_a\n\ndef func_b():\n    pass\n")
        findings = await agent.analyze(_make_scope([a, b]))
        assert any(f.rule_id == "DR-001" for f in findings)


@pytest.mark.asyncio
async def test_no_circular_warning():
    agent = DesignReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        a = Path(td) / "module_a.py"
        b = Path(td) / "module_b.py"
        a.write_text("import module_b\n\ndef func_a():\n    pass\n")
        b.write_text("def func_b():\n    pass\n")
        findings = await agent.analyze(_make_scope([a, b]))
        assert not any(f.rule_id == "DR-001" for f in findings)


# ── DR-002: God class ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_god_class():
    agent = DesignReviewerAgent()
    lines = ["class GodClass:"]
    for i in range(20):
        lines.append(f"    def method{i}(self):\n        pass\n")
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("\n".join(lines))
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any("DR-002" == f.rule_id for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_small_class():
    agent = DesignReviewerAgent()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("class Small:\n    def m1(self):\n        pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "DR-002" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── DR-003: High coupling ────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_high_coupling():
    agent = DesignReviewerAgent()
    imports = "\n".join([f"import mod{i}" for i in range(15)])
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text(imports + "\ndef f():\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "DR-003" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_allows_normal_imports():
    agent = DesignReviewerAgent()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("import os\nimport sys\nfrom pathlib import Path\ndef f():\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "DR-003" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── DR-004: Deep inheritance ─────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_deep_inheritance():
    agent = DesignReviewerAgent()
    with tempfile.TemporaryDirectory() as td:
        chain = Path(td) / "chain.py"
        chain.write_text("""
class A:
    pass
class B(A):
    pass
class C(B):
    pass
class D(C):
    pass
class E(D):
    pass
""")
        findings = await agent.analyze(_make_scope([chain]))
        assert any(f.rule_id == "DR-004" for f in findings)


@pytest.mark.asyncio
async def test_allows_shallow_inheritance():
    agent = DesignReviewerAgent()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("class Parent:\n    pass\nclass Child(Parent):\n    pass\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "DR-004" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── DR-005: Large abstract class ─────────────────────────────────

@pytest.mark.asyncio
async def test_detects_large_abstract_class():
    agent = DesignReviewerAgent()
    abs_methods = "\n".join([
        f"    def abstract{i}(self):\n        pass\n"
        for i in range(8)
    ])
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text(f"class BigInterface:\n{abs_methods}\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "DR-005" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Clean Code ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_code_no_issues():
    agent = DesignReviewerAgent()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("""
import os
from pathlib import Path

class Base:
    def common(self):
        return True

class Service(Base):
    def do_work(self):
        return self.common()
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert len(findings) == 0
    finally:
        f.unlink(missing_ok=True)


# ── Category ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_have_design_category():
    agent = DesignReviewerAgent()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("class X:\n" + "".join([f"    def m{i}(self):\n        pass\n" for i in range(20)]))
    try:
        findings = await agent.analyze(_make_scope([f]))
        for finding in findings:
            assert finding.category == FindingCategory.DESIGN
    finally:
        f.unlink(missing_ok=True)
