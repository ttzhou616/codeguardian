"""Tests for the BaseAgent class."""

import asyncio

import pytest

from codeguardian.agents.base import BaseAgent
from codeguardian.agents.static_analysis import StaticAnalysisAgent
from codeguardian.agents.security_scanner import SecurityScannerAgent
from codeguardian.bus import MessageBus
from codeguardian.models.findings import ChangeScope, Finding, Severity


# A concrete agent for testing the base class
class _TestAgent(BaseAgent):
    topic = "test_agent"

    def __init__(self, findings_to_return=None, **kwargs):
        super().__init__(name="test_agent", **kwargs)
        self.findings_to_return = findings_to_return or []
        self.setup_called = False
        self.teardown_called = False

    async def setup(self):
        self.setup_called = True

    async def teardown(self):
        self.teardown_called = True

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        return self.findings_to_return


@pytest.mark.asyncio
async def test_agent_lifecycle(bus):
    """Setup and teardown should be called during run()."""
    agent = _TestAgent(bus=bus)
    assert not agent.setup_called
    assert not agent.teardown_called

    scope = ChangeScope()
    findings = await agent.run(scope)

    assert agent.setup_called
    assert agent.teardown_called
    assert findings == []


@pytest.mark.asyncio
async def test_agent_publishes_findings(bus):
    """Run should publish findings on the bus."""

    class Captor:
        def __init__(self):
            self.received = []

        async def on_findings(self, msg):
            self.received.extend(msg.payload)

    captor = Captor()
    await bus.subscribe("findings", captor.on_findings)

    finding = Finding(
        file_path="test.py",
        line_start=1,
        line_end=1,
        title="Test finding",
        severity=Severity.INFO,
    )
    agent = _TestAgent(bus=bus, findings_to_return=[finding])

    result = await agent.run(ChangeScope())

    assert len(result) == 1
    assert result[0].agent_id == agent.agent_id
    assert len(captor.received) == 1


@pytest.mark.asyncio
async def test_disabled_agent_skips_analysis(bus):
    """When an agent is disabled, run() should return empty list immediately."""
    from codeguardian.config import AgentConfig

    config = AgentConfig(enabled=False)
    agent = _TestAgent(bus=bus, config=config)

    findings = await agent.run(ChangeScope())
    assert findings == []
    assert not agent.setup_called


@pytest.mark.asyncio
async def test_agent_id_is_unique():
    """Each agent should have a unique ID."""
    agent1 = _TestAgent()
    agent2 = _TestAgent()
    assert agent1.agent_id != agent2.agent_id


@pytest.mark.asyncio
async def test_all_subclass_agents_can_instantiate():
    """Smoke test: ensure all agent subclasses can be instantiated."""
    agents = [
        StaticAnalysisAgent("static_analysis"),
        SecurityScannerAgent("security_scanner"),
    ]
    for agent in agents:
        assert agent.name
        assert agent.agent_id
        findings = await agent.analyze(ChangeScope())
        assert isinstance(findings, list)
