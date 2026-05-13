"""Tests for the PerformanceAnalyzerAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.performance_analyzer import PerformanceAnalyzerAgent
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


# ── PA-001: N+1 Query ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_n_plus_one():
    agent = PerformanceAnalyzerAgent()
    code = """def get_users(ids):
    results = []
    for uid in ids:
        user = db.execute("SELECT * FROM users WHERE id = ?", uid)
        results.append(user)
    return results
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any("PA-001" == f.rule_id for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_no_n_plus_one_without_loop():
    agent = PerformanceAnalyzerAgent()
    f = _write_temp("def get_user():\n    return db.execute('SELECT * FROM users')\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "PA-001" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── PA-002: list.append in loop ──────────────────────────────────

@pytest.mark.asyncio
async def test_detects_append_in_loop():
    agent = PerformanceAnalyzerAgent()
    code = """def make_list(items):
    result = []
    for item in items:
        result.append(item * 2)
    return result
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-002" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── PA-003: String += in loop ────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_string_concat_in_loop():
    agent = PerformanceAnalyzerAgent()
    code = """def build_html(parts):
    html = ""
    for p in parts:
        html += "<div>" + p + "</div>"
    return html
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-003" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── PA-004: Repeated attr in loop ────────────────────────────────

@pytest.mark.asyncio
async def test_detects_repeated_attr_in_loop():
    agent = PerformanceAnalyzerAgent()
    code = """def process(config):
    total = 0
    for item in config.settings.items:
        if config.settings.threshold > 0:
            total += item.value * config.settings.ratio
    return total
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-004" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── PA-005: range(len(...)) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_range_len():
    agent = PerformanceAnalyzerAgent()
    code = """def bad_iter(items):
    for i in range(len(items)):
        print(items[i])
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-005" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_enumerate_is_fine():
    agent = PerformanceAnalyzerAgent()
    code = """def good_iter(items):
    for i, item in enumerate(items):
        print(i, item)
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert not any(f.rule_id == "PA-005" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Non-Python Rules ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_js_n_plus_one():
    agent = PerformanceAnalyzerAgent()
    f = _write_temp("items.forEach(i => db.find({id: i.id}));\n", suffix=".js")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-010" for f in findings)
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_dom_in_loop():
    agent = PerformanceAnalyzerAgent()
    f = _write_temp("for (let i=0;i<10;i++) { document.getElementById('x'); }\n", suffix=".js")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert any(f.rule_id == "PA-012" for f in findings)
    finally:
        f.unlink(missing_ok=True)


# ── Clean Code ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_code_no_issues():
    agent = PerformanceAnalyzerAgent()
    code = """def process(items):
    settings = config.settings
    ratio = settings.ratio
    return [item * ratio for item in items if item > settings.threshold]
"""
    f = _write_temp(code)
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert len(findings) == 0
    finally:
        f.unlink(missing_ok=True)


# ── Category ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_findings_have_performance_category():
    agent = PerformanceAnalyzerAgent()
    f = _write_temp("def f(xs):\n    r=[]\n    for x in xs:\n        r.append(x)\n    return r\n")
    try:
        findings = await agent.analyze(_make_scope([f]))
        for finding in findings:
            assert finding.category == FindingCategory.PERFORMANCE
    finally:
        f.unlink(missing_ok=True)
