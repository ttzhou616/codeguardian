"""Performance analyzer agent — N+1 queries, memory leaks, lock contention."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class PerformanceAnalyzerAgent(BaseAgent):
    topic = "performance_analyzer"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: detect performance anti-patterns
        return findings
