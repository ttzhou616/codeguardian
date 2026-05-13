"""Orchestrator — coordinates all review agents and merges results."""

from __future__ import annotations

import asyncio
from typing import Optional

from codeguardian.agents.base import BaseAgent
from codeguardian.config import CodeGuardianSettings, load_config
from codeguardian.models.findings import ChangeScope, Finding, ReviewReport
from codeguardian.synthesizer import Synthesizer


class Orchestrator(BaseAgent):
    """Root agent that dispatches work to specialized agents and collects results."""

    topic = "orchestrator"

    def __init__(self, config: CodeGuardianSettings | None = None):
        self.settings = config or load_config()
        super().__init__(name="orchestrator")
        self._agents: dict[str, BaseAgent] = {}
        self.synthesizer = Synthesizer()

    def register(self, agent: BaseAgent) -> None:
        """Register a review agent with the orchestrator."""
        self._agents[agent.name] = agent

    def register_all(self, agents: list[BaseAgent]) -> None:
        for a in agents:
            self.register(a)

    def _route(self, scope: ChangeScope) -> list[BaseAgent]:
        """Select which agents should review the given change scope.

        Routing logic (Phase 2 will refine with language-aware mapping):
        - .sql files → security_scanner, performance_analyzer
        - .py/.ts/.js → all agents
        - .md/.yaml → style_checker only
        """
        enabled = [a for a in self._agents.values() if a.enabled]
        if not enabled:
            return []
        return enabled  # For now, route everything to all enabled agents

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        """Run all registered agents in parallel, collect their findings."""
        agents = self._route(scope)
        if not agents:
            await self.log("info", "No agents enabled for this scope")
            return []

        await self.log("info", f"Dispatching {len(agents)} agents")

        results = await asyncio.gather(
            *(agent.run(scope) for agent in agents),
            return_exceptions=True,
        )

        all_findings: list[Finding] = []
        for agent, result in zip(agents, results):
            if isinstance(result, Exception):
                await self.log("error", f"Agent {agent.name} failed: {result}")
            else:
                all_findings.extend(result)

        return self.synthesizer.process(all_findings)

    async def review(self, scope: ChangeScope) -> ReviewReport:
        """Entry point: run a full review and return the report."""
        findings = await self.run(scope)
        return ReviewReport(
            change_scope=scope,
            findings=findings,
            risk_score=self.synthesizer.calculate_risk_score(findings),
            review_score=self.synthesizer.calculate_review_score(findings),
        )
