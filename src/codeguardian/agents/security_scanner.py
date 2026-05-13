"""Security scanner agent — SQL injection, XSS, secrets detection."""

from codeguardian.agents.base import BaseAgent
from codeguardian.models.findings import ChangeScope, Finding


class SecurityScannerAgent(BaseAgent):
    topic = "security_scanner"

    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        findings: list[Finding] = []
        # Phase 2: integrate Semgrep rules, CWE checks, secret scanning
        return findings
