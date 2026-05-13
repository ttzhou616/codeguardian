"""Design reviewer agent — SOLID, coupling, architecture patterns."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class DesignReviewerAgent(BaseAgent):
    topic = "design_reviewer"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: analyze module dependencies, interface contracts
        return findings
