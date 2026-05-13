"""Shared test fixtures."""

import pytest

from codeguardian.bus import MessageBus, reset_bus
from codeguardian.config import AgentConfig
from codeguardian.models.findings import (
    ChangeScope,
    ChangedFile,
    Finding,
    FindingCategory,
    Severity,
)


@pytest.fixture(autouse=True)
def _reset_bus():
    """Reset the global message bus before each test."""
    reset_bus()
    yield
    reset_bus()


@pytest.fixture
def bus():
    return MessageBus()


@pytest.fixture
def agent_config():
    return AgentConfig()


@pytest.fixture
def sample_finding():
    return Finding(
        file_path="src/app.py",
        line_start=42,
        line_end=42,
        title="Unused variable",
        description="Variable 'temp' is assigned but never used",
        severity=Severity.WARNING,
        category=FindingCategory.STATIC,
        rule_id="CG-001",
    )


@pytest.fixture
def sample_change_scope():
    return ChangeScope(
        changed_files=[
            ChangedFile(path="src/app.py", status="modified", additions=10, deletions=3),
            ChangedFile(path="src/models.py", status="added", additions=50, deletions=0),
        ]
    )
