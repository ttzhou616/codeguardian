"""Test reviewer agent — coverage gaps, boundary conditions, mock quality."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class TestReviewerAgent(BaseAgent):
    topic = "test_reviewer"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: analyze test coverage, boundary conditions
        return findings
