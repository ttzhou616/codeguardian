"""Tests for the SecurityScannerAgent."""

import tempfile
from pathlib import Path

import pytest

from codeguardian.agents.security_scanner import SecurityScannerAgent
from codeguardian.models.findings import ChangeScope, ChangedFile, Severity


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


# ── SQL Injection ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_string_concat_sql():
    agent = SecurityScannerAgent()
    f = _write_temp('query = "SELECT * FROM users WHERE id = " + user_id')
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-001" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_fstring_sql():
    agent = SecurityScannerAgent()
    f = _write_temp("""query = f"SELECT * FROM users WHERE name = '{name}'" """)
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-002" in rule_ids
    finally:
        f.unlink(missing_ok=True)


# ── Secrets ────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_hardcoded_password():
    agent = SecurityScannerAgent()
    f = _write_temp('password = "admin123"')
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-010" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_hardcoded_api_key():
    agent = SecurityScannerAgent()
    f = _write_temp('API_KEY = "sk-abcdefghijklmnop"')
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-011" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_private_key():
    agent = SecurityScannerAgent()
    f = _write_temp("key = '''-----BEGIN RSA PRIVATE KEY-----\\nabc123\\n-----END RSA PRIVATE KEY-----'''")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-013" in rule_ids
    finally:
        f.unlink(missing_ok=True)


# ── Dangerous Functions ────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_eval():
    agent = SecurityScannerAgent()
    f = _write_temp("result = eval(user_input)")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-030" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_os_system():
    agent = SecurityScannerAgent()
    f = _write_temp("os.system('rm -rf ' + path)")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-031" in rule_ids
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_detects_shell_true():
    agent = SecurityScannerAgent()
    f = _write_temp("subprocess.run(cmd, shell=True)")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-031" in rule_ids
    finally:
        f.unlink(missing_ok=True)


# ── Clean Code ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clean_code_no_findings():
    agent = SecurityScannerAgent()
    f = _write_temp("""
def get_user(user_id: int) -> dict:
    conn = get_db()
    result = conn.execute(
        "SELECT * FROM users WHERE id = ?",
        (user_id,)
    ).fetchone()
    return dict(result)
""")
    try:
        findings = await agent.analyze(_make_scope([f]))
        assert len(findings) == 0
    finally:
        f.unlink(missing_ok=True)


# ── Severity Filtering ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_severity_threshold_filters():
    from codeguardian.config import AgentConfig

    config = AgentConfig(severity_threshold=Severity.CRITICAL)
    agent = SecurityScannerAgent(config=config)

    # This code triggers SEC-030 (eval → WARNING) which should be filtered
    f = _write_temp("result = eval(data)")
    try:
        findings = await agent.analyze(_make_scope([f]))
        # WARNING is below CRITICAL threshold, so should be filtered out
        assert len([f for f in findings if f.rule_id == "SEC-030"]) == 0
    finally:
        f.unlink(missing_ok=True)


# ── File Extension Filtering ──────────────────────────────────

@pytest.mark.asyncio
async def test_python_only_rule_not_fired_on_yaml():
    """Rules with file_extensions should only match those file types."""
    agent = SecurityScannerAgent()
    # SEC-002 (fstring SQL) only applies to .py files
    f = _write_temp('query = f"SELECT * FROM {table}"', suffix=".txt")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-002" not in rule_ids  # .txt shouldn't match Python-only rule
    finally:
        f.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_universal_rule_fires_on_any_extension():
    """Rules without file_extensions should match all file types."""
    agent = SecurityScannerAgent()
    # SEC-010 (password) has no file_extensions, should fire on any file
    f = _write_temp("password = 'secret'", suffix=".cfg")
    try:
        findings = await agent.analyze(_make_scope([f]))
        rule_ids = {f.rule_id for f in findings}
        assert "SEC-010" in rule_ids
    finally:
        f.unlink(missing_ok=True)
