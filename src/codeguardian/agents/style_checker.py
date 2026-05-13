"""Style checker agent — naming conventions, formatting, consistency."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class StyleCheckerAgent(BaseAgent):
    topic = "style_checker"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: integrate custom style rules
        return findings
