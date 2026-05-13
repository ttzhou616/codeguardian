"""Agent base class and lifecycle management."""

from __future__ import annotations

import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Optional

from codeguardian.bus import MessageBus, get_bus
from codeguardian.config import AgentConfig
from codeguardian.models.findings import ChangeScope, Finding


class BaseAgent(ABC):
    """Abstract base for all review agents.

    Each agent subscribes to a topic on the message bus, performs its
    analysis in `analyze()`, and publishes findings back.
    """

    topic: str = ""

    def __init__(
        self,
        name: str,
        config: AgentConfig | None = None,
        bus: MessageBus | None = None,
    ) -> None:
        self._name = name
        self._config = config or AgentConfig()
        self._bus = bus or get_bus()
        self._id = f"{name}-{uuid.uuid4().hex[:8]}"
        self._running = False

    @property
    def agent_id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def enabled(self) -> bool:
        return self._config.enabled

    @property
    def bus(self) -> MessageBus:
        return self._bus

    async def setup(self) -> None:
        """Called once before the agent starts processing."""

    async def teardown(self) -> None:
        """Called once when the agent is stopped."""

    @abstractmethod
    async def analyze(self, scope: ChangeScope) -> list[Finding]:
        """Run analysis on the given change scope. Must be implemented by subclasses."""
        ...

    async def log(self, level: str, message: str) -> None:
        """Publish a log message on the agent's topic."""
        await self._bus.publish(
            topic=self.topic,
            payload={"level": level, "message": message, "agent": self._name},
            sender_id=self._id,
        )

    async def run(self, scope: ChangeScope) -> list[Finding]:
        """Full lifecycle: setup → analyze → teardown."""
        if not self.enabled:
            return []
        await self.setup()
        try:
            findings = await self.analyze(scope)
            for f in findings:
                f.agent_id = self._id
            await self._bus.publish(
                topic="findings",
                payload=findings,
                sender_id=self._id,
            )
            return findings
        except Exception:
            await self.log("error", f"Agent {self._name} failed during analysis")
            return []
        finally:
            await self.teardown()
