"""LLM-based false positive filter using DeepSeek API (or compatible)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import httpx

from codeguardian.models.findings import Finding, Severity


class LLMFilter:
    """Uses an LLM to analyze findings in context and filter false positives."""

    SYSTEM_PROMPT = """You are a code review expert. Your job:
1. Analyze each finding against the source code context.
2. Determine if it's a TRUE POSITIVE (real issue) or FALSE POSITIVE (safe code).
3. Consider: test files, documentation examples, type stubs, configuration files.
4. Return judgment with confidence (0.0-1.0) and reasoning.

FALSE POSITIVE examples:
- "password = 'test'" in test_login.py (test data)
- "eval()" inside ast.literal_eval (safe wrapper)
- "SELECT * FROM" in a docstring or comment
- "API_KEY = os.environ['KEY']" (loaded from env, not hardcoded)

TRUE POSITIVE examples:
- "password = 'admin123'" in app.py (production code)
- "os.system(user_input)" in a route handler (command injection)
- "SELECT * FROM " + request.args (SQL injection in production)

Respond in JSON: {"findings": [{"id": "...", "is_false_positive": true/false, "confidence": 0.95, "reasoning": "..."}]}"""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "deepseek-chat",
        base_url: str = "https://api.deepseek.com",
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    async def filter(
        self, findings: list[Finding], source_files: dict[str, str] | None = None,
    ) -> list[Finding]:
        """Return findings with false positives removed."""
        if not self.enabled or not findings:
            return findings

        # Build context for LLM
        context = self._build_context(findings, source_files or {})
        if not context:
            return findings

        try:
            response = await self._call_llm(context)
            if not response:
                return findings
            return self._apply_filter(findings, response)
        except Exception:
            return findings  # Fail open — don't block review on LLM error

    def _build_context(
        self, findings: list[Finding], source_files: dict[str, str],
    ) -> str:
        """Build prompt with findings and source code snippets."""
        lines = ["## Findings to review\n"]

        for i, f in enumerate(findings[:20]):  # Limit batch size
            lines.append(f"### Finding {i}")
            lines.append(f"- Rule: {f.rule_id}")
            lines.append(f"- Title: {f.title}")
            lines.append(f"- File: {f.file_path}")
            lines.append(f"- Line: {f.line_start}-{f.line_end}")
            lines.append(f"- Severity: {f.severity.value}")
            lines.append(f"- Description: {f.description}")

            # Include surrounding source code
            source = source_files.get(f.file_path)
            if source:
                snippet = self._extract_snippet(source, f.line_start, f.line_end)
                lines.append(f"- Source context:\n```\n{snippet}\n```")
            lines.append("")

        return "\n".join(lines)

    async def _call_llm(self, context: str) -> dict | None:
        """Send context to LLM and parse response."""
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.base_url}/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": self.SYSTEM_PROMPT},
                        {"role": "user", "content": context},
                    ],
                    "temperature": 0.1,
                    "max_tokens": 2000,
                },
            )

        if resp.status_code != 200:
            return None

        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            # Extract JSON from response (may be wrapped in markdown code block)
            if "```" in content:
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content)
        except (KeyError, json.JSONDecodeError, IndexError):
            return None

    def _apply_filter(
        self, findings: list[Finding], response: dict,
    ) -> list[Finding]:
        """Remove findings that the LLM flagged as false positives."""
        llm_results = response.get("findings", [])
        if not llm_results:
            return findings

        false_ids: set[int] = set()
        adjusted: dict[int, str] = {}

        for result in llm_results:
            idx = result.get("id", -1)
            if isinstance(idx, str) and idx.isdigit():
                idx = int(idx)
            if result.get("is_false_positive") and result.get("confidence", 0) >= 0.7:
                false_ids.add(idx)
            elif result.get("confidence", 0) >= 0.9:
                adjusted[idx] = result.get("reasoning", "")

        return [
            f for i, f in enumerate(findings)
            if i not in false_ids
        ]

    @staticmethod
    def _extract_snippet(
        source: str, line_start: int, line_end: int, context_lines: int = 3,
    ) -> str:
        """Extract source code around a finding with context."""
        lines = source.split("\n")
        start = max(0, line_start - context_lines - 1)
        end = min(len(lines), line_end + context_lines)
        snippet = []
        for i in range(start, end):
            marker = ">>>" if line_start - 1 <= i <= line_end - 1 else "   "
            snippet.append(f"{marker} {i+1}: {lines[i]}")
        return "\n".join(snippet)
