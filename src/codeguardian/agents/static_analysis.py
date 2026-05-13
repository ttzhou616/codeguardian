"""Static analysis agent — complexity, dead code, type safety."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class StaticAnalysisAgent(BaseAgent):
    topic = "static_analysis"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: integrate tree-sitter for AST-level analysis
        return findings
