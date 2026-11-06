import pytest

from src.engine.executor import ExerciseExecutor
from src.providers.demo import DemoProvider
from src.sandbox.orchestrator import SandboxOrchestrator
from src.scenarios.registry import ScenarioRegistry


@pytest.mark.asyncio
async def test_all_scenarios_run_attack_and_defense_in_offline_lab():
    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        registry = ScenarioRegistry()
        executor = ExerciseExecutor(DemoProvider(), sandbox)
        receipts = []
        for scenario in registry.list_core():
            attack = await executor.run_attack(scenario)
            retest = await executor.retest(scenario, scenario.defense_prompt or "")
            receipts.append((attack.scenario_id, attack.phase, retest.phase))

        assert receipts == [
            (scenario.id, "attack", "retest") for scenario in registry.list_core()
        ]
    finally:
        sandbox.stop()


@pytest.mark.asyncio
async def test_offline_sa01_demonstrates_enforced_confirmation_gate():
    sandbox = SandboxOrchestrator()
    sandbox.start()
    try:
        scenario = ScenarioRegistry().get("SA-01")
        executor = ExerciseExecutor(DemoProvider(), sandbox)
        attack = await executor.run_attack(scenario)
        retest = await executor.retest(scenario, scenario.defense_prompt)

        assert attack.evaluator_result.assessment == "attempt_detected"
        assert attack.evidence.control_decisions[0]["reason"] == "separate_confirmation_required"
        assert attack.evidence.control_decisions[0]["executed"] is False
        assert retest.evaluator_result.assessment == "resisted"
        assert retest.tool_calls == []
    finally:
        sandbox.stop()
