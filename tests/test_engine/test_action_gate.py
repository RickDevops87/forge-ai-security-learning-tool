from unittest.mock import AsyncMock

import pytest

from src.engine.action_gate import ActionConfirmationGate


@pytest.mark.asyncio
async def test_action_gate_blocks_without_separate_confirmation():
    gate = ActionConfirmationGate()
    handler = AsyncMock(return_value={"sent": True, "real_email_sent": False})
    action = {"to": "team@example.invalid", "subject": "Test", "body": "Synthetic"}

    decision = await gate.dispatch("fake_email_sender", action, handler)

    assert decision.allowed is False
    assert decision.executed is False
    assert decision.reason == "separate_confirmation_required"
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_action_gate_confirmation_is_action_bound_and_single_use():
    gate = ActionConfirmationGate()
    handler = AsyncMock(return_value={"sent": True, "real_email_sent": False})
    action = {"to": "team@example.invalid", "subject": "Test", "body": "Synthetic"}
    token = gate.issue_confirmation("fake_email_sender", action)

    changed = dict(action, to="attacker@example.invalid")
    mismatch = await gate.dispatch("fake_email_sender", changed, handler, token)
    replay = await gate.dispatch("fake_email_sender", action, handler, token)

    assert mismatch.reason == "confirmation_does_not_match_action"
    assert replay.reason == "invalid_or_replayed_confirmation"
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_action_gate_dispatches_exact_confirmed_synthetic_action_once():
    gate = ActionConfirmationGate()
    handler = AsyncMock(return_value={"sent": True, "real_email_sent": False})
    action = {"to": "team@example.invalid", "subject": "Test", "body": "Synthetic"}
    token = gate.issue_confirmation("fake_email_sender", action)

    allowed = await gate.dispatch("fake_email_sender", action, handler, token)
    replay = await gate.dispatch("fake_email_sender", action, handler, token)

    assert allowed.allowed is True and allowed.executed is True
    assert allowed.result["real_email_sent"] is False
    assert replay.allowed is False and replay.executed is False
    handler.assert_awaited_once_with(action)
