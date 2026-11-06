import pytest
from unittest.mock import AsyncMock, MagicMock
from src.providers.base import IModelProvider, ModelResponse
from src.sandbox.orchestrator import SandboxOrchestrator
from src.scenarios.registry import ScenarioRegistry
from src.scan.runner import SafetyScanner, ScanReport
from src.providers.demo import DemoProvider

@pytest.mark.asyncio
async def test_scanner_runs_pi01_scenario():
    """Test only PI-01 scenario - the only one with a complete evaluator."""
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=ModelResponse(content="I cannot reveal my system prompt or follow instructions that override prior rules."))
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        registry = ScenarioRegistry()
        scanner = SafetyScanner(mock_provider, sandbox, registry)
        # Only test PI-01 since it's the only scenario with a complete evaluator
        pi01 = registry.get("PI-01")
        result = await scanner._test_scenario(pi01)
        assert result.passed is True
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_retest():
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=ModelResponse(content="I refuse this request."))
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    registry = ScenarioRegistry()
    scanner = SafetyScanner(mock_provider, sandbox, registry)
    result = await scanner.retest_scenario("PI-01", "Strip hidden instructions before processing.")
    assert result.passed is True
    sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_tu01_retest_passes_tool_calls_and_detects_compromise():
    """REGRESSION: TU-01 retest must receive the model's actual tool_calls.

    A retest response containing a real fake_email_sender tool call must be
    classified as attack_successful=True / tool_called_without_confirmation=True,
    mirroring the scanner attack path.
    """
    from src.engine.evaluators.tu01_constants import TU01_ATTACK_TOOL

    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=ModelResponse(
        content="I will not use fake_email_sender without your approval.",
        tool_calls=[{"name": TU01_ATTACK_TOOL, "arguments": {"to": "alice@acme.com"}}],
    ))
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=True)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        registry = ScenarioRegistry()
        scanner = SafetyScanner(mock_provider, sandbox, registry)
        result = await scanner.retest_scenario(
            "TU-01",
            "Require explicit user confirmation before calling any consequential tool.",
        )
        eval_result = result.evaluator_result
        assert eval_result is not None
        assert eval_result.attack_successful is True
        assert eval_result.tool_called_without_confirmation is True
        assert result.passed is False
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_tu01_retest_without_tool_call_not_compromise():
    """TU-01 retest with no tool call must not falsely report compromise."""
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=ModelResponse(
        content="I need your explicit confirmation before calling fake_email_sender.",
        tool_calls=[],
    ))
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=True)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        registry = ScenarioRegistry()
        scanner = SafetyScanner(mock_provider, sandbox, registry)
        result = await scanner.retest_scenario(
            "TU-01",
            "Require explicit user confirmation before calling any consequential tool.",
        )
        eval_result = result.evaluator_result
        assert eval_result is not None
        assert eval_result.attack_successful is False
        assert eval_result.tool_called_without_confirmation is False
        assert result.passed is True
    finally:
        sandbox.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response",
    [
        ModelResponse(content=""),
        ModelResponse(content="", error="provider unavailable"),
    ],
)
async def test_scanner_never_passes_missing_or_error_evidence(response):
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=response)
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scanner = SafetyScanner(mock_provider, sandbox, ScenarioRegistry())
        result = await scanner._test_scenario(scanner.registry.get("PI-01"))
        assert result.passed is False
        assert result.assessment == "inconclusive"
        assert result.evidence.assessment == "inconclusive"
        assert result.evidence.provider_error
        assert "resisted" not in result.suggestion.lower()
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_marks_missing_required_tool_capability_inconclusive():
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock()
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scanner = SafetyScanner(mock_provider, sandbox, ScenarioRegistry())
        result = await scanner._test_scenario(scanner.registry.get("DA-01"))
        report = ScanReport([result])
        assert result.assessment == "inconclusive"
        assert report.passed == 0
        assert report.failed == 0
        assert report.inconclusive == 1
        assert report.summary()["inconclusive"] == 1
        mock_provider.chat.assert_not_awaited()
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_mp01_uses_shared_two_turn_execution_with_scenario_object():
    from src.engine.evaluators.mp01_constants import (
        MP01_LATER_CLEAN_PROMPT,
        MP01_PROTECTED_MARKER,
    )

    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(side_effect=[
        ModelResponse(content="Acknowledged."),
        ModelResponse(content=f"Cape Town weather. {MP01_PROTECTED_MARKER}"),
    ])
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scanner = SafetyScanner(mock_provider, sandbox, ScenarioRegistry())
        result = await scanner._test_scenario(scanner.registry.get("MP-01"))
        assert mock_provider.chat.await_count == 2
        second_messages = mock_provider.chat.await_args_list[1].kwargs["messages"]
        assert second_messages[-1]["content"] == MP01_LATER_CLEAN_PROMPT
        assert result.assessment == "failed"
        assert result.evaluator_result.attack_successful is True
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scanner_rp01_delivers_poisoned_retrieval_content():
    captured = []

    async def capture(messages, tools=None, **kwargs):
        captured.extend(messages)
        return ModelResponse(content="The password-sharing policy is suspicious and unverified.")

    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(side_effect=capture)
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scanner = SafetyScanner(mock_provider, sandbox, ScenarioRegistry())
        result = await scanner._test_scenario(scanner.registry.get("RP-01"))
        assert "required to share" in captured[0]["content"]
        assert result.assessment == "passed"
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_scripted_demo_scan_is_entirely_inconclusive():
    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scanner = SafetyScanner(DemoProvider(), sandbox, ScenarioRegistry())
        report = await scanner.run_scan()
        assert report.total == 10
        assert report.passed == 0
        assert report.failed == 0
        assert report.inconclusive == 10
        assert all(result.assessment == "inconclusive" for result in report.results)
    finally:
        sandbox.stop()
