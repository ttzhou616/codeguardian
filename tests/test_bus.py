"""Tests for the message bus."""

import asyncio

import pytest

from codeguardian.bus import MessageBus, get_bus, reset_bus


class CaptureCallback:
    """Captures received messages for test assertions."""

    def __init__(self):
        self.messages = []

    async def __call__(self, message):
        self.messages.append(message)


@pytest.mark.asyncio
async def test_publish_to_single_subscriber(bus):
    captor = CaptureCallback()
    await bus.subscribe("test.topic", captor)
    await bus.publish("test.topic", {"key": "value"}, sender_id="test-agent")

    assert len(captor.messages) == 1
    assert captor.messages[0].topic == "test.topic"
    assert captor.messages[0].payload == {"key": "value"}
    assert captor.messages[0].sender_id == "test-agent"


@pytest.mark.asyncio
async def test_publish_to_multiple_subscribers(bus):
    captor1 = CaptureCallback()
    captor2 = CaptureCallback()

    await bus.subscribe("test.topic", captor1)
    await bus.subscribe("test.topic", captor2)
    await bus.publish("test.topic", "hello")

    assert len(captor1.messages) == 1
    assert len(captor2.messages) == 1


@pytest.mark.asyncio
async def test_no_subscribers_silently_succeeds(bus):
    """Publishing to a topic with no subscribers should not raise."""
    await bus.publish("empty.topic", "data")
    assert bus.subscriber_count("empty.topic") == 0


@pytest.mark.asyncio
async def test_unsubscribe(bus):
    captor = CaptureCallback()
    await bus.subscribe("test.topic", captor)
    await bus.publish("test.topic", "first")
    assert len(captor.messages) == 1

    await bus.unsubscribe("test.topic", captor)
    await bus.publish("test.topic", "second")
    assert len(captor.messages) == 1  # No new messages


@pytest.mark.asyncio
async def test_subscriber_count(bus):
    captor = CaptureCallback()
    assert bus.subscriber_count("test.topic") == 0

    await bus.subscribe("test.topic", captor)
    assert bus.subscriber_count("test.topic") == 1

    await bus.unsubscribe("test.topic", captor)
    assert bus.subscriber_count("test.topic") == 0


def test_get_bus_singleton():
    reset_bus()
    bus1 = get_bus()
    bus2 = get_bus()
    assert bus1 is bus2
