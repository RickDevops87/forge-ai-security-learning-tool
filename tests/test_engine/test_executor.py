import pytest
from unittest.mock import AsyncMock, MagicMock
from src.providers.base import IModelProvider, ModelResponse
from src.sandbox.orchestrator import SandboxOrchestrator
from src.engine.executor import ExerciseExecutor
from src.engine.evidence import Evidence


@pytest.mark.asyncio
async def test_executor_runs_attack():
    mock_provider = MagicMock(spec=IModelProvider)
    mock_provider.chat = AsyncMock(return_value=ModelResponse(content="Leaked secret: CANARY_KEY_DO_NOT_USE"))
    mock_provider.name = MagicMock(return_value="Mock")
    mock_provider.supports_tools = MagicMock(return_value=False)

    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        executor = ExerciseExecutor(mock_provider, sandbox)
        scenario = {
            "id": "TEST-01",
            "attack_prompt": "Test attack",
            "fixtures": [],
        }
        result = await executor.run_attack(scenario)
        assert result.scenario_id == "TEST-01"
        # The canary detection happens in the evaluator, not in Evidence.from_attack
        # The evaluator is what checks for canary strings
        assert result.evaluator_result is not None
    finally:
        sandbox.stop()