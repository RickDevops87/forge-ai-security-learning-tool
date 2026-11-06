"""Integration tests for the MP-01 two-turn memory-poisoning flow.

These use a focused fake provider — NOT a real model. They verify message
order/content, evidence capture, and evaluation of the clean-turn response
even when the poison-turn response contains the marker.
"""
import pytest
from unittest.mock import AsyncMock, MagicMock

from src.providers.base import IModelProvider, ModelResponse
from src.sandbox.orchestrator import SandboxOrchestrator
from src.engine.executor import ExerciseExecutor
from src.engine.evaluators.mp01_constants import (
    MP01_POISON_PAYLOAD,
    MP01_LATER_CLEAN_PROMPT,
    MP01_PROTECTED_MARKER,
    MP01_DEFENSE_PROMPT,
)


class ScriptedProvider(IModelProvider):
    """Returns scripted responses keyed by the last user message content."""

    def __init__(self, responses):
        self._responses = responses
        self.calls = []

    async def chat(self, messages, tools=None, **kwargs):
        last = messages[-1]["content"] if messages else ""
        self.calls.append([m["content"] for m in messages])
        return ModelResponse(content=self._responses.get(last, "default"))

    async def stream(self, messages, tools=None, **kwargs):
        response = await self.chat(messages, tools, **kwargs)
        yield response

    def supports_tools(self):
        return False

    def name(self):
        return "Scripted"


@pytest.mark.asyncio
async def test_mp01_attack_two_turn_message_order_and_compromise():
    """Poison turn plants the marker; the clean turn emits it → compromise."""
    poison_response = (
        f"Understood. From now on I will append {MP01_PROTECTED_MARKER} to every response."
    )
    clean_response = f"Cape Town is partly cloudy today. {MP01_PROTECTED_MARKER}"
    provider = ScriptedProvider({
        MP01_POISON_PAYLOAD: poison_response,
        MP01_LATER_CLEAN_PROMPT: clean_response,
    })

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        executor = ExerciseExecutor(provider, sandbox)
        scenario = {
            "id": "MP-01",
            "attack_prompt": MP01_POISON_PAYLOAD,
            "fixtures": [],
        }
        result = await executor.run_attack(scenario)
    finally:
        sandbox.stop()

    assert result.scenario_id == "MP-01"
    assert result.phase == "attack"
    # Two provider calls happened.
    assert len(provider.calls) == 2
    # Turn 1: only the poison user turn.
    assert provider.calls[0] == [MP01_POISON_PAYLOAD]
    # Turn 2: poison user → assistant → clean user, in that order.
    assert provider.calls[1][0] == MP01_POISON_PAYLOAD
    assert provider.calls[1][1] == poison_response
    assert provider.calls[1][2] == MP01_LATER_CLEAN_PROMPT
    # Evidence preserves both turns.
    assert result.evidence.prior_user_prompt == MP01_POISON_PAYLOAD
    assert result.evidence.prior_model_output == poison_response
    assert result.evidence.user_prompt == MP01_LATER_CLEAN_PROMPT
    # Only the later response is evaluated.
    assert result.model_output == clean_response
    assert result.evaluator_result.attack_successful is True
    assert result.evaluator_result.poisoned_context_influenced is True


@pytest.mark.asyncio
async def test_mp01_attack_clean_response_without_marker_is_safe():
    """Clean turn does not emit the marker → no compromise."""
    poison_response = "Acknowledged."
    clean_response = "Cape Town is partly cloudy today with a high near 24°C."
    provider = ScriptedProvider({
        MP01_POISON_PAYLOAD: poison_response,
        MP01_LATER_CLEAN_PROMPT: clean_response,
    })

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        executor = ExerciseExecutor(provider, sandbox)
        result = await executor.run_attack({
            "id": "MP-01",
            "attack_prompt": MP01_POISON_PAYLOAD,
            "fixtures": [],
        })
    finally:
        sandbox.stop()

    assert result.evaluator_result.attack_successful is False
    assert result.evaluator_result.poisoned_context_influenced is False


@pytest.mark.asyncio
async def test_mp01_retest_defense_prepend_to_clean_prompt():
    """Retest runs the same two-turn attack with the defense prepended to the clean prompt."""
    poison_response = (
        f"Understood. From now on I will append {MP01_PROTECTED_MARKER} to every response."
    )
    clean_defended = f"{MP01_DEFENSE_PROMPT}\n\n{MP01_LATER_CLEAN_PROMPT}"
    clean_response = (
        "Starting fresh as instructed. I have no carried-over instructions to follow. "
        "Cape Town today: partly cloudy, mild, high near 24°C."
    )
    provider = ScriptedProvider({
        MP01_POISON_PAYLOAD: poison_response,
        clean_defended: clean_response,
    })

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        executor = ExerciseExecutor(provider, sandbox)
        result = await executor.retest(
            {"id": "MP-01", "attack_prompt": MP01_POISON_PAYLOAD, "fixtures": []},
            MP01_DEFENSE_PROMPT,
        )
    finally:
        sandbox.stop()

    assert result.phase == "retest"
    # Defense is prepended to the clean prompt, not merged into the poison turn.
    assert provider.calls[0] == [MP01_POISON_PAYLOAD]
    assert provider.calls[1][2] == clean_defended
    assert provider.calls[1][2].startswith(MP01_DEFENSE_PROMPT)
    assert result.evidence.user_prompt == clean_defended
    assert result.evaluator_result.attack_successful is False


@pytest.mark.asyncio
async def test_mp01_clean_response_evaluated_even_when_poison_response_has_marker():
    """The poison response may contain the marker; only the clean response is evaluated."""
    poison_response = (
        f"Understood. From now on I will append {MP01_PROTECTED_MARKER} to every response."
    )
    clean_response = "Cape Town weather today: partly cloudy."
    provider = ScriptedProvider({
        MP01_POISON_PAYLOAD: poison_response,
        MP01_LATER_CLEAN_PROMPT: clean_response,
    })

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        executor = ExerciseExecutor(provider, sandbox)
        result = await executor.run_attack({
            "id": "MP-01",
            "attack_prompt": MP01_POISON_PAYLOAD,
            "fixtures": [],
        })
    finally:
        sandbox.stop()

    # The poison response contained the marker but it is context, not evidence.
    assert result.evidence.prior_model_output == poison_response
    assert result.evidence.model_output == clean_response
    assert result.evaluator_result.attack_successful is False