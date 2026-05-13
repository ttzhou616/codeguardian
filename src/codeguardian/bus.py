"""Async message bus for agent communication."""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

Callback = Callable[[Any], Awaitable[None]]


@dataclass
class Message:
    topic: str
    payload: Any
    sender_id: str = ""


class MessageBus:
    """Publish/subscribe event system with async callback support."""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callback]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def publish(self, topic: str, payload: Any, sender_id: str = "") -> None:
        """Publish a message to a topic. All subscriber callbacks fire concurrently."""
        message = Message(topic=topic, payload=payload, sender_id=sender_id)
        callbacks = self._subscribers.get(topic, [])
        if not callbacks:
            return
        await asyncio.gather(*(cb(message) for cb in callbacks))

    async def subscribe(self, topic: str, callback: Callback) -> None:
        """Register a callback for a topic."""
        async with self._lock:
            self._subscribers[topic].append(callback)

    async def unsubscribe(self, topic: str, callback: Callback) -> None:
        """Remove a callback from a topic."""
        async with self._lock:
            if topic in self._subscribers:
                self._subscribers[topic] = [
                    cb for cb in self._subscribers[topic] if cb is not callback
                ]

    def subscriber_count(self, topic: str) -> int:
        return len(self._subscribers.get(topic, []))


_bus_instance: MessageBus | None = None


def get_bus() -> MessageBus:
    """Get or create the global MessageBus singleton."""
    global _bus_instance
    if _bus_instance is None:
        _bus_instance = MessageBus()
    return _bus_instance


def reset_bus() -> None:
    """Reset the global bus instance (for testing)."""
    global _bus_instance
    _bus_instance = None
