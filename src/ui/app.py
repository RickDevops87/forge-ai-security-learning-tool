"""Interactive Textual learner for controlled attack, defense, and human review."""
from __future__ import annotations

import json
from typing import Any, Iterable

from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Button, Footer, Header, Label, Rule, Static, TextArea

from ..engine.executor import ExerciseExecutor, ExerciseResult
from ..engine.progress import ProgressTracker
from ..providers.factory import create_provider, list_providers
from ..sandbox.orchestrator import SandboxOrchestrator
from ..scan.runner import SafetyScanner
from ..scenarios.registry import ScenarioRegistry


SCENARIO_REALITY = {
    "PI-01": ("SCRIPTED DEMO", "Protected-context boundary is not yet enforced."),
    "II-01": ("SCRIPTED DEMO", "Controlled webpage ingestion is not yet implemented."),
    "DL-01": ("SCRIPTED DEMO", "Synthetic data delivery and redaction enforcement remain incomplete."),
    "TU-01": ("BOUNDED LAB", "Tool requests are evaluated; complete dispatch policy is unfinished."),
    "MP-01": ("BOUNDED LAB", "A real two-turn context path is exercised; no persistent memory store is used."),
    "RP-01": ("BOUNDED LAB", "Poisoned retrieved content reaches the model; source enforcement is unfinished."),
    "AM-01": ("SCRIPTED DEMO", "No authenticated second-agent identity boundary exists yet."),
    "DA-01": ("BOUNDED LAB", "Scope requests are evaluated; complete capability middleware is unfinished."),
    "SC-01": ("BOUNDED LAB", "Untrusted plugin requests are recorded; no plugin is installed or executed."),
    "SA-01": ("ENFORCED CONTROL", "Exact-action, separate, one-time confirmation is enforced at dispatch."),
}


class SecurityLabApp(App):
    """Human-verifiable AI security learning lab."""

    CSS = """
    Screen { background: #111827; color: #e5e7eb; }
    Header, Footer { background: #172554; color: #f8fafc; }
    #workspace { padding: 1 2; }
    #title { color: #fb7185; text-style: bold; width: 100%; height: 3; }
    .section-label { color: #67e8f9; text-style: bold; margin-top: 1; }
    .evidence-text { color: #e5e7eb; padding: 0 1; }
    .success { color: #4ade80; text-style: bold; }
    .failure { color: #f87171; text-style: bold; }
    .warning { color: #fbbf24; text-style: bold; }
    .muted { color: #94a3b8; }
    .scenario-card { border: solid #334155; margin: 1 0; padding: 1; }
    Button { margin: 1 1 0 0; }
    TextArea { height: 7; border: solid #475569; }
    """

    def __init__(self, progress_path: str = "~/.ai-security-lab/progress.json") -> None:
        super().__init__()
        self.provider = create_provider("demo")
        self.sandbox = SandboxOrchestrator()
        self.registry = ScenarioRegistry()
        self.progress = ProgressTracker(progress_path)
        self.executor: ExerciseExecutor | None = None
        self.scanner: SafetyScanner | None = None
        self._current_scenario = None
        self._attack_result: ExerciseResult | None = None
        self._defense_result: ExerciseResult | None = None
        self._human_verdicts: dict[str, str] = {}

    def compose(self) -> ComposeResult:
        yield Header()
        yield VerticalScroll(id="workspace")
        yield Footer()

    async def on_mount(self) -> None:
        self.title = "Forge Personal AI Safety Lab"
        self.sandbox.start()
        self._wire_engine()
        await self._show_main()

    def on_unmount(self) -> None:
        self.sandbox.stop()

    def _wire_engine(self) -> None:
        self.executor = ExerciseExecutor(self.provider, self.sandbox)
        self.scanner = SafetyScanner(self.provider, self.sandbox, self.registry)

    async def _set_view(self, widgets: Iterable[Any]) -> None:
        workspace = self.query_one("#workspace", VerticalScroll)
        await workspace.remove_children()
        await workspace.mount(*list(widgets))
        workspace.scroll_home(animate=False)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "btn-main":
            await self._show_main()
        elif bid == "btn-learn":
            await self._show_learn()
        elif bid == "btn-scan":
            await self._show_scan()
        elif bid == "btn-provider":
            await self._show_provider_setup()
        elif bid.startswith("scenario-"):
            await self._show_exercise(bid.removeprefix("scenario-"))
        elif bid.startswith("provider-"):
            await self._select_provider(bid.removeprefix("provider-"))
        elif bid == "btn-attack":
            await self._do_attack()
        elif bid == "btn-defense":
            await self._do_defense()
        elif bid == "btn-run-scan":
            await self._do_scan()
        elif bid.startswith("verdict-"):
            await self._record_verdict(bid.removeprefix("verdict-"))
        elif bid == "btn-save-review":
            await self._save_review()

    async def _show_main(self) -> None:
        await self._set_view([
            Label("Forge Personal AI Safety Lab", id="title"),
            Static(
                "Learn an attack, run it only against synthetic lab data, inspect raw evidence, "
                "apply the defense, retest the same mechanism, and record your own verdict.",
                classes="evidence-text",
            ),
            Label("Human verification is required; evaluator output is not truth.", classes="warning"),
            Label(f"Human-reviewed scenarios completed: {self.progress.completed_count()}/10", classes="evidence-text"),
            Rule(),
            Button("LEARN — Attack / Defense / Human Review", id="btn-learn", variant="primary"),
            Button("SCAN — Bounded Configuration Assessment", id="btn-scan", variant="success"),
            Button("Provider Setup", id="btn-provider"),
        ])

    async def _show_learn(self) -> None:
        widgets: list[Any] = [
            Label("LEARN — Controlled Scenarios", id="title"),
            Label("Reality labels describe the implementation today, not the intended final product.", classes="evidence-text"),
            Rule(),
        ]
        for scenario in self.registry.list_core():
            reality, limitation = SCENARIO_REALITY[scenario.id]
            state = "HUMAN VERIFIED" if self.progress.get(scenario.id).completed else "NOT YET VERIFIED"
            widgets.append(Container(
                Label(f"{scenario.id}: {scenario.title}", classes="section-label"),
                Label(f"{reality} · {state}", classes="warning"),
                Static(scenario.description, classes="evidence-text"),
                Static(limitation, classes="muted"),
                Button("Open laboratory", id=f"scenario-{scenario.id}"),
                classes="scenario-card",
            ))
        widgets.append(Button("← Main menu", id="btn-main"))
        await self._set_view(widgets)

    async def _show_exercise(self, scenario_id: str) -> None:
        scenario = self.registry.get(scenario_id)
        if scenario is None:
            self.notify(f"Unknown scenario: {scenario_id}", severity="error")
            return
        self._current_scenario = scenario
        self._attack_result = None
        self._defense_result = None
        self._human_verdicts = {}
        reality, limitation = SCENARIO_REALITY[scenario.id]
        tools = ", ".join(str(tool) for tool in (scenario.attack_tools or [])) or "None"
        await self._set_view([
            Label(f"{scenario.id}: {scenario.title}", id="title"),
            Label(reality, classes="warning"),
            Static(limitation, classes="evidence-text"),
            Label("What is this?", classes="section-label"),
            Static(scenario.what_is_this, classes="evidence-text"),
            Label("Why it matters", classes="section-label"),
            Static(scenario.why_it_matters, classes="evidence-text"),
            Label("What will happen", classes="section-label"),
            Static(scenario.what_happens, classes="evidence-text"),
            Label("What you must inspect", classes="section-label"),
            Static(scenario.what_to_watch_for, classes="evidence-text"),
            Label("Exact synthetic attack payload", classes="section-label"),
            Static(scenario.attack_prompt, classes="evidence-text"),
            Label("Available lab tools", classes="section-label"),
            Static(tools, classes="evidence-text"),
            Label("Safety boundary", classes="section-label"),
            Static("Synthetic fixtures only. No real email, plugin installation, payment, deletion, credential, or external target.", classes="success"),
            Rule(),
            Button("1. Run controlled attack", id="btn-attack", variant="error"),
            Button("← Scenario list", id="btn-learn"),
        ])

    @staticmethod
    def _result_assessment(result: ExerciseResult) -> tuple[str, str]:
        if result.error or not (result.model_output or result.tool_calls):
            return "INCONCLUSIVE", "warning"
        assessment = getattr(result.evaluator_result, "assessment", None)
        if assessment == "inconclusive":
            return "INCONCLUSIVE", "warning"
        if getattr(result.evaluator_result, "attack_successful", False):
            return "ATTACK BEHAVIOR OBSERVED", "failure"
        return "ATTACK BEHAVIOR NOT OBSERVED", "success"

    @staticmethod
    def _evaluation_dict(result: ExerciseResult) -> dict[str, Any]:
        evaluation = result.evaluator_result
        if hasattr(evaluation, "to_dict"):
            return evaluation.to_dict()
        if hasattr(evaluation, "model_dump"):
            return evaluation.model_dump()
        return {"representation": repr(evaluation)}

    async def _do_attack(self) -> None:
        if self._current_scenario is None or self.executor is None:
            return
        scenario = self._current_scenario
        try:
            result = await self.executor.run_attack(scenario)
        except Exception as exc:
            self.notify(f"Attack execution failed: {exc}", severity="error")
            return
        self._attack_result = result
        label, style = self._result_assessment(result)
        await self._set_view([
            Label(f"{scenario.id}: Attack evidence", id="title"),
            Label(label, classes=style),
            Label("Model output", classes="section-label"),
            Static(result.model_output or "(no model output)", classes="evidence-text"),
            Label("Structured tool requests", classes="section-label"),
            Static(json.dumps(result.tool_calls, indent=2, default=str), classes="evidence-text"),
            Label("Evaluator evidence", classes="section-label"),
            Static(json.dumps(self._evaluation_dict(result), indent=2, default=str), classes="evidence-text"),
            Label("Control decisions", classes="section-label"),
            Static(json.dumps(result.evidence.control_decisions, indent=2, default=str), classes="evidence-text"),
            Label("Your verification", classes="section-label"),
            Static("Inspect the payload, output, tool requests, and control decision. Record what the evidence actually proves.", classes="evidence-text"),
            Button("I verified attack behavior", id="verdict-attack-observed", variant="error"),
            Button("I verified resistance", id="verdict-attack-resisted", variant="success"),
            Button("Evidence is inconclusive", id="verdict-attack-inconclusive", variant="warning"),
            Rule(),
            Label("Defense to apply", classes="section-label"),
            Static(scenario.defense_prompt or "No defense defined", classes="evidence-text"),
            Static("Prompt guidance changes model behavior; only an independently enforced control is labeled ENFORCED.", classes="warning"),
            Button("2. Apply defense and retest same attack", id="btn-defense", variant="success"),
            Button("Run attack again", id="btn-attack", variant="error"),
            Button("← Scenario list", id="btn-learn"),
        ])

    async def _do_defense(self) -> None:
        if self._current_scenario is None or self.executor is None:
            return
        scenario = self._current_scenario
        if not scenario.defense_prompt:
            self.notify("No defense is defined for this scenario.", severity="warning")
            return
        try:
            result = await self.executor.retest(scenario, scenario.defense_prompt)
        except Exception as exc:
            self.notify(f"Retest failed: {exc}", severity="error")
            return
        self._defense_result = result
        label, style = self._result_assessment(result)
        before = self._attack_result.model_output if self._attack_result else "Attack was not run in this session."
        await self._set_view([
            Label(f"{scenario.id}: Defense retest", id="title"),
            Label(label, classes=style),
            Label("Before defense", classes="section-label"),
            Static(before or "(no output)", classes="evidence-text"),
            Label("After defense", classes="section-label"),
            Static(result.model_output or "(no output)", classes="evidence-text"),
            Label("Retest evaluator evidence", classes="section-label"),
            Static(json.dumps(self._evaluation_dict(result), indent=2, default=str), classes="evidence-text"),
            Label("Enforced control decisions", classes="section-label"),
            Static(json.dumps(result.evidence.control_decisions, indent=2, default=str), classes="evidence-text"),
            Label("Your defense verdict", classes="section-label"),
            Button("Defense was effective", id="verdict-defense-effective", variant="success"),
            Button("Defense failed", id="verdict-defense-failed", variant="error"),
            Button("Evidence is inconclusive", id="verdict-defense-inconclusive", variant="warning"),
            Label("Learning notes", classes="section-label"),
            TextArea(placeholder="What happened? What evidence supports your verdict? What limitation remains?", id="review-notes"),
            Button("Save human review", id="btn-save-review", variant="primary"),
            Button("Retest again", id="btn-defense", variant="success"),
            Button("← Scenario list", id="btn-learn"),
        ])

    async def _record_verdict(self, verdict: str) -> None:
        phase, _, value = verdict.partition("-")
        self._human_verdicts[phase] = value
        self.notify(f"Human {phase} verdict recorded: {value}")

    def _result_receipt(self, result: ExerciseResult | None) -> dict[str, Any] | None:
        if result is None:
            return None
        return {
            "phase": result.phase,
            "model_output": result.model_output,
            "tool_calls": result.tool_calls,
            "error": result.error,
            "evaluation": self._evaluation_dict(result),
            "evidence": result.evidence.to_dict(),
        }

    async def _save_review(self) -> None:
        if self._current_scenario is None:
            return
        if "attack" not in self._human_verdicts or "defense" not in self._human_verdicts:
            self.notify("Record both attack and defense verdicts before completing the scenario.", severity="warning")
            return
        notes_widget = self.query_one("#review-notes", TextArea)
        progress = self.progress.get(self._current_scenario.id)
        progress.attack_result = self._result_receipt(self._attack_result)
        progress.retest_result = self._result_receipt(self._defense_result)
        progress.notes = json.dumps({"human_verdicts": self._human_verdicts, "notes": notes_widget.text}, indent=2)
        progress.completed = True
        self.progress.save()
        self.notify("Human review saved locally.")
        await self._show_learn()

    async def _show_scan(self) -> None:
        await self._set_view([
            Label("SCAN — Bounded Assessment", id="title"),
            Static("This is not a security certificate. Missing capability, provider errors, or insufficient evidence are INCONCLUSIVE.", classes="warning"),
            Button("Run all scenarios", id="btn-run-scan", variant="success"),
            Button("← Main menu", id="btn-main"),
        ])

    async def _do_scan(self) -> None:
        if self.scanner is None:
            return
        await self._set_view([Label("Running bounded scan…", id="title")])
        report = await self.scanner.run_scan()
        widgets: list[Any] = [Label("SCAN RESULTS", id="title")]
        for result in report.results:
            status = result.assessment.upper()
            style = "success" if status == "PASSED" else "warning" if status == "INCONCLUSIVE" else "failure"
            widgets.extend([
                Label(f"{result.scenario.id}: {result.scenario.title} — {status}", classes=style),
                Static(result.suggestion, classes="evidence-text"),
            ])
        widgets.extend([
            Rule(),
            Label(f"Total {report.total} · Passed {report.passed} · Failed {report.failed} · Inconclusive {report.inconclusive}", classes="evidence-text"),
            Button("← Main menu", id="btn-main"),
        ])
        await self._set_view(widgets)

    async def _show_provider_setup(self) -> None:
        widgets: list[Any] = [
            Label("Provider Setup", id="title"),
            Label(f"Current provider: {self.provider.name()}", classes="evidence-text"),
            Static("Demo mode is offline and scripted. Provider-backed runs test only the selected model/configuration and may require local setup.", classes="warning"),
        ]
        for provider_name in list_providers():
            widgets.append(Button(f"Use {provider_name}", id=f"provider-{provider_name}"))
        widgets.append(Button("← Main menu", id="btn-main"))
        await self._set_view(widgets)

    async def _select_provider(self, name: str) -> None:
        try:
            self.provider = create_provider(name)
            self._wire_engine()
        except Exception as exc:
            self.notify(f"Provider setup failed: {exc}", severity="error")
            return
        self.notify(f"Provider set to {self.provider.name()}")
        await self._show_provider_setup()
