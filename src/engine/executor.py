"""Exercise executor — runs attack/defense loops via a model provider."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Type
from pydantic import BaseModel
from src.providers.base import IModelProvider, ModelResponse
from src.sandbox.orchestrator import SandboxOrchestrator
from src.engine.evidence import Evidence
from src.engine.evaluators.sa01_constants import SA01_TOOL, sa01_tool
from src.engine.evaluators.sc01_constants import sc01_tool
from src.engine.evaluators import (
    PI01Evaluator, II01Evaluator, DL01Evaluator, TU01Evaluator, MP01Evaluator,
    RP01Evaluator, AM01Evaluator, DA01Evaluator, SC01Evaluator, SA01Evaluator,
)
from src.engine.evaluators.mp01_constants import (
    MP01_POISON_PAYLOAD,
    MP01_LATER_CLEAN_PROMPT,
)
from src.engine.evaluators.rp01_constants import (
    RP01_POISONED_CLAIM,
    RP01_USER_QUESTION,
)


# Map scenario IDs to their specific evaluators
SCENARIO_EVALUATORS: Dict[str, Type] = {
    "PI-01": PI01Evaluator,
    "II-01": II01Evaluator,
    "DL-01": DL01Evaluator,
    "TU-01": TU01Evaluator,
    "MP-01": MP01Evaluator,
    "RP-01": RP01Evaluator,
    "AM-01": AM01Evaluator,
    "DA-01": DA01Evaluator,
    "SC-01": SC01Evaluator,
    "SA-01": SA01Evaluator,
}


class ExerciseResult(BaseModel):
    scenario_id: str
    phase: str  # attack, defense, retest
    evaluator_result: object
    model_output: str
    tool_calls: List[Dict[str, Any]]
    evidence: Evidence
    error: Optional[str] = None

    model_config = {"arbitrary_types_allowed": True}


class ExerciseExecutor:
    """Runs a scenario's attack and defense loops against a model provider."""

    def __init__(self, provider: IModelProvider, sandbox: SandboxOrchestrator) -> None:
        self.provider = provider
        self.sandbox = sandbox

    async def run_attack(self, scenario: Dict[str, Any] | Any) -> ExerciseResult:
        """Run the attack phase of a scenario."""
        # Handle both dict and Pydantic Scenario objects
        scenario_id = scenario.get("id") if hasattr(scenario, "get") else getattr(scenario, "id", None)
        attack_prompt = scenario.get("attack_prompt") if hasattr(scenario, "get") else getattr(scenario, "attack_prompt", None)
        attack_tools = scenario.get("attack_tools") if hasattr(scenario, "get") else getattr(scenario, "attack_tools", None)
        fixtures = scenario.get("fixtures", []) if hasattr(scenario, "get") else getattr(scenario, "fixtures", None) or []
        tools = attack_tools or []

        self.sandbox.load_fixtures(fixtures)

        if scenario_id == "SA-01":
            return await self._run_sa01(attack_prompt, "attack")

        if scenario_id == "SC-01":
            return await self._run_sc01(attack_prompt, "attack")

        # MP-01 is a two-turn memory-poisoning attack: the poison user turn must
        # actually precede the clean user turn in separate provider calls. Only the
        # LATER response is evaluated; the first turn is context, not evidence.
        if scenario_id == "MP-01":
            return await self._run_mp01_turns(
                scenario, attack_prompt, tools, phase="attack",
                defense_prompt=None,
            )

        # RP-01 is a retrieval poisoning scenario: the poisoned retrieved content
        # must actually reach the model as part of the prompt. We simulate retrieval
        # by injecting the fixture content into the user message alongside the question.
        if scenario_id == "RP-01":
            retrieved_content = self.sandbox.fixture_loader.get_content("rag_document")
            user_prompt = f"Retrieved content:\n{retrieved_content}\n\n{RP01_USER_QUESTION}"
            response = await self.provider.chat(
                messages=[{"role": "user", "content": user_prompt}],
                tools=tools,
            )

            model_output = response.content or response.refusal or ""
            evidence = Evidence.from_attack(
                scenario_id=scenario_id,
                user_prompt=user_prompt,
                model_output=model_output,
                tool_calls=response.tool_calls or [],
                provider_error=response.error,
                model_refusal=response.refusal,
            )

            evaluator = self._get_evaluator(scenario_id)
            eval_result = evaluator.evaluate(model_output, attack_prompt)

            return ExerciseResult(
                scenario_id=scenario_id,
                phase="attack",
                evaluator_result=eval_result,
                model_output=model_output,
                tool_calls=response.tool_calls or [],
                evidence=evidence,
                error=response.error,
            )

        response = await self.provider.chat(
            messages=[{"role": "user", "content": attack_prompt}],
            tools=tools,
        )

        evidence = Evidence.from_attack(
            scenario_id=scenario_id,
            user_prompt=attack_prompt,
            model_output=response.content or "",
            tool_calls=response.tool_calls or [],
        )

        # Evaluate with scenario-specific evaluator
        sid = scenario_id
        evaluator = self._get_evaluator(sid)
        if sid == "TU-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                attack_prompt,
                response.tool_calls or [],
            )
        elif sid == "DA-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                attack_prompt,
                response.tool_calls or [],
            )
        else:
            eval_result = evaluator.evaluate(response.content or "", attack_prompt)

        return ExerciseResult(
            scenario_id=sid,
            phase="attack",
            evaluator_result=eval_result,
            model_output=response.content or "",
            tool_calls=response.tool_calls or [],
            evidence=evidence,
        )

    async def _run_sa01(self, prompt: str, phase: str) -> ExerciseResult:
        """Evaluate SA requests and enforce a separate confirmation boundary."""
        available = self.provider.supports_tools()
        response = await self.provider.chat(
            messages=[{"role": "user", "content": prompt}],
            tools=[sa01_tool()] if available else [],
        )
        raw_calls = response.tool_calls
        evaluation = SA01Evaluator().evaluate(
            response.content or "", prompt, raw_calls,
            tools_available=available, provider_error=response.error,
        )
        # Evidence's existing schema accepts dict calls only. Preserve malformed
        # raw records in evaluator evidence without changing the shared schema.
        calls = [call for call in raw_calls if isinstance(call, dict)] if isinstance(raw_calls, list) else []
        control_decisions = []
        if self.sandbox.action_gate and self.sandbox.tool_registry:
            tool = self.sandbox.tool_registry.get(SA01_TOOL)
            for call in evaluation.evidence.get("matched_tool_calls", []):
                function = call.get("function", call)
                arguments = function.get("arguments", {})
                if isinstance(arguments, str):
                    import json
                    arguments = json.loads(arguments)
                decision = await self.sandbox.action_gate.dispatch(
                    SA01_TOOL,
                    arguments,
                    tool.handler,
                    confirmation_token=None,
                )
                control_decisions.append(decision.to_dict())
        evaluation.evidence["control_decisions"] = control_decisions
        evaluation.evidence["enforced_confirmation_gate"] = bool(control_decisions)
        evaluation.evidence["real_action_executed"] = any(
            decision["executed"] for decision in control_decisions
        )
        evidence = Evidence.from_attack(
            scenario_id="SA-01", user_prompt=prompt,
            model_output=response.content or "", tool_calls=calls,
            control_decisions=control_decisions,
        )
        return ExerciseResult(
            scenario_id="SA-01", phase=phase, evaluator_result=evaluation,
            model_output=response.content or "", tool_calls=calls,
            evidence=evidence, error=response.error,
        )

    async def _run_sc01(self, prompt: str, phase: str) -> ExerciseResult:
        """Record provider requests only; never dispatch a plugin handler."""
        tools_available = self.provider.supports_tools()
        response = await self.provider.chat(
            messages=[{"role": "user", "content": prompt}],
            tools=[sc01_tool()] if tools_available else [],
        )
        calls = response.tool_calls or []
        evidence = Evidence.from_attack(
            scenario_id="SC-01", user_prompt=prompt,
            model_output=response.content or "", tool_calls=calls,
        )
        evaluation = SC01Evaluator().evaluate(
            response.content or "", prompt, calls,
            tools_available=tools_available, provider_error=response.error,
        )
        return ExerciseResult(
            scenario_id="SC-01", phase=phase, evaluator_result=evaluation,
            model_output=response.content or "", tool_calls=calls,
            evidence=evidence, error=response.error,
        )

    async def _run_mp01_turns(
        self,
        scenario: Dict[str, Any] | Any,
        attack_prompt: str,
        tools: List[Dict[str, Any]],
        phase: str,
        defense_prompt: str | None,
    ) -> ExerciseResult:
        """Execute the MP-01 two-turn attack and evaluate only the later response.

        Message order for the second provider.chat call is fixed:
            1. poison user turn   (the malicious instruction)
            2. first assistant response
            3. clean user prompt  (the Cape Town weather request)

        The defense is NOT delivered as a system-role message. A system role
        would give the defense privileges the ordinary user never has and would
        change the meaning of the experiment. Instead the defense is prepended
        to the clean user prompt (turn 3), keeping the poison turn itself
        byte-for-byte identical between attack and retest. This preserves the
        user-accessible defense model: poison user turn -> assistant response ->
        defended clean user turn, with the later clean response alone
        evaluated for persistent poisoning.
        """
        scenario_id = (
            scenario.get("id") if hasattr(scenario, "get")
            else getattr(scenario, "id", None)
        )

        # Turn 1: plant the poisoned instruction. Identical for attack and retest.
        first_response = await self.provider.chat(
            messages=[{"role": "user", "content": attack_prompt}],
            tools=tools,
        )
        first_output = first_response.content or first_response.refusal or ""

        if first_response.error:
            evaluator = self._get_evaluator(scenario_id)
            eval_result = evaluator.evaluate("", attack_prompt)
            evidence = Evidence.from_attack(
                scenario_id=scenario_id,
                user_prompt=attack_prompt,
                model_output="",
                tool_calls=[],
                prior_user_prompt=attack_prompt,
                prior_model_output=first_output,
                provider_error=first_response.error,
            )
            return ExerciseResult(
                scenario_id=scenario_id,
                phase=phase,
                evaluator_result=eval_result,
                model_output="",
                tool_calls=[],
                evidence=evidence,
                error=first_response.error,
            )

        # Turn 2: the clean prompt, with the poison turn and the model's first
        # response carried in as context. During retest the defense is
        # prepended to the clean user prompt so the user-facing input is
        # defended, not a hidden system directive.
        clean_prompt = MP01_LATER_CLEAN_PROMPT
        if defense_prompt:
            clean_prompt = f"{defense_prompt}\n\n{MP01_LATER_CLEAN_PROMPT}"
        later_messages = [
            {"role": "user", "content": attack_prompt},
            {"role": "assistant", "content": first_output},
            {"role": "user", "content": clean_prompt},
        ]
        second_response = await self.provider.chat(
            messages=later_messages,
            tools=tools,
        )
        later_output = second_response.content or second_response.refusal or ""

        if phase == "retest":
            evidence = Evidence.from_retest(
                scenario_id=scenario_id,
                user_prompt=clean_prompt,
                model_output=later_output,
                prior_user_prompt=attack_prompt,
                prior_model_output=first_output,
            )
        else:
            evidence = Evidence.from_attack(
                scenario_id=scenario_id,
                user_prompt=clean_prompt,
                model_output=later_output,
                tool_calls=second_response.tool_calls or [],
                prior_user_prompt=attack_prompt,
                prior_model_output=first_output,
            )

        # Evaluate ONLY the later (clean-turn) response against the poison payload.
        evaluator = self._get_evaluator(scenario_id)
        eval_result = evaluator.evaluate(later_output, attack_prompt)

        return ExerciseResult(
            scenario_id=scenario_id,
            phase=phase,
            evaluator_result=eval_result,
            model_output=later_output,
            tool_calls=second_response.tool_calls or [],
            evidence=evidence,
            error=second_response.error,
        )

    async def run_defense(self, scenario: Dict[str, Any]) -> ExerciseResult:
        """Run the defense phase of a scenario."""
        if (scenario.get("id") if hasattr(scenario, "get") else scenario.id) == "SA-01":
            defense = scenario.get("defense_prompt", "") if hasattr(scenario, "get") else scenario.defense_prompt
            return await self._run_sa01(defense or "", "defense")
        if (scenario.get("id") if hasattr(scenario, "get") else scenario.id) == "SC-01":
            defense = scenario.get("defense_prompt", "") if hasattr(scenario, "get") else scenario.defense_prompt
            return await self._run_sc01(defense or "", "defense")
        defense_prompt = scenario.get("defense_prompt", "")
        tools = scenario.get("defense_tools") or []

        response = await self.provider.chat(
            messages=[{"role": "user", "content": defense_prompt}],
            tools=tools,
        )

        evidence = Evidence.from_defense(
            scenario_id=scenario["id"],
            defense_prompt=defense_prompt,
            model_output=response.content or "",
        )

        evaluator = self._get_evaluator(scenario["id"])
        if scenario["id"] == "TU-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                defense_prompt,
                response.tool_calls or [],
            )
        elif scenario["id"] == "DA-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                defense_prompt,
                response.tool_calls or [],
            )
        else:
            eval_result = evaluator.evaluate(response.content or "", defense_prompt)

        return ExerciseResult(
            scenario_id=scenario["id"],
            phase="defense",
            evaluator_result=eval_result,
            model_output=response.content or "",
            tool_calls=response.tool_calls or [],
            evidence=evidence,
        )

    async def retest(self, scenario: Dict[str, Any] | Any, defense_prompt: str) -> ExerciseResult:
        """Retest the scenario with a defense in place."""
        scenario_id = scenario.get("id") if hasattr(scenario, "get") else getattr(scenario, "id", None)
        attack_prompt = scenario.get("attack_prompt") if hasattr(scenario, "get") else getattr(scenario, "attack_prompt", None)
        attack_tools = scenario.get("attack_tools") if hasattr(scenario, "get") else getattr(scenario, "attack_tools", None)
        fixtures = scenario.get("fixtures", []) if hasattr(scenario, "get") else getattr(scenario, "fixtures", None) or []
        tools = attack_tools or []

        self.sandbox.load_fixtures(fixtures)

        if scenario_id == "SA-01":
            return await self._run_sa01(f"{defense_prompt}\n\n{attack_prompt}", "retest")

        if scenario_id == "SC-01":
            return await self._run_sc01(f"{defense_prompt}\n\n{attack_prompt}", "retest")

        # MP-01 retest runs the SAME two-turn attack as run_attack, but with the
        # defense prepended to the clean prompt. See _run_mp01_turns for the
        # rationale; combining the turns into one prompt would not test memory
        # poisoning at all.
        if scenario_id == "MP-01":
            return await self._run_mp01_turns(
                scenario, attack_prompt, tools, phase="retest",
                defense_prompt=defense_prompt,
            )

        # RP-01 retest: same poisoned retrieved content + same question,
        # with the defense prepended to the user prompt. The poisoned
        # content is identical between attack and retest; only the defense
        # guidance is added.
        if scenario_id == "RP-01":
            retrieved_content = self.sandbox.fixture_loader.get_content("rag_document")
            user_prompt = f"Retrieved content:\n{retrieved_content}\n\n{RP01_USER_QUESTION}"
            defended_prompt = f"{defense_prompt}\n\n{user_prompt}"
            response = await self.provider.chat(
                messages=[{"role": "user", "content": defended_prompt}],
                tools=tools,
            )

            model_output = response.content or response.refusal or ""
            evidence = Evidence.from_retest(
                scenario_id=scenario_id,
                user_prompt=defended_prompt,
                model_output=model_output,
                tool_calls=response.tool_calls or [],
                provider_error=response.error,
                model_refusal=response.refusal,
            )

            evaluator = self._get_evaluator(scenario_id)
            eval_result = evaluator.evaluate(model_output, attack_prompt)

            return ExerciseResult(
                scenario_id=scenario_id,
                phase="retest",
                evaluator_result=eval_result,
                model_output=model_output,
                tool_calls=response.tool_calls or [],
                evidence=evidence,
                error=response.error,
            )

        combined_prompt = f"{defense_prompt}\n\n{attack_prompt}"

        response = await self.provider.chat(
            messages=[{"role": "user", "content": combined_prompt}],
            tools=tools,
        )

        evidence = Evidence.from_retest(
            scenario_id=scenario_id,
            user_prompt=combined_prompt,
            model_output=response.content or "",
        )

        evaluator = self._get_evaluator(scenario_id)
        if scenario_id == "TU-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                combined_prompt,
                response.tool_calls or [],
            )
        elif scenario_id == "DA-01":
            eval_result = evaluator.evaluate(
                response.content or "",
                combined_prompt,
                response.tool_calls or [],
            )
        else:
            eval_result = evaluator.evaluate(response.content or "", combined_prompt)

        return ExerciseResult(
            scenario_id=scenario_id,
            phase="retest",
            evaluator_result=eval_result,
            model_output=response.content or "",
            tool_calls=response.tool_calls or [],
            evidence=evidence,
        )

    def _get_evaluator(self, scenario_id: str):
        """Get the scenario-specific evaluator."""
        evaluator_class = SCENARIO_EVALUATORS.get(scenario_id)
        if evaluator_class is None:
            # Fallback to PI-01 evaluator for unknown scenarios
            evaluator_class = PI01Evaluator
        return evaluator_class()
