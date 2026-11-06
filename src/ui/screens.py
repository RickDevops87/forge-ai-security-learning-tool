"""Additional UI screens for the TUI."""
from __future__ import annotations

from textual.app import ComposeResult
from textual.widgets import Static, Button, Label, Rule, ScrollView
from textual.containers import Container


class ExerciseScreen(Container):
    """Displays an exercise with inline explanations."""

    def __init__(self, scenario: Any) -> None:
        super().__init__()
        self.scenario = scenario

    def compose(self) -> ComposeResult:
        yield Label(f"Scenario: {self.scenario.title}", id="exercise-title")
        yield Rule()

        # Expandable explanations
        yield Label("What is this?", id="expander-label")
        yield Static(self.scenario.what_is_this, id="expander-what")

        yield Label("Why does it matter?", id="expander-label")
        yield Static(self.scenario.why_it_matters, id="expander-why")

        yield Label("What is about to happen?", id="expander-label")
        yield Static(self.scenario.what_happens, id="expander-what-happens")

        yield Label("What should I watch for?", id="expander-label")
        yield Static(self.scenario.what_to_watch_for, id="expander-watch")

        yield Button("Run Attack", id="btn-attack", variant="error")
        yield Button("Apply Defense", id="btn-defense", variant="success")
        yield Button("← Back", id="btn-back", variant="default")


class ScanResultsScreen(Container):
    """Displays AI Safety Scan results."""

    def __init__(self, report: Any) -> None:
        super().__init__()
        self.report = report

    def compose(self) -> ComposeResult:
        yield Label("AI Safety Scan — Results", id="scan-title")
        yield Rule()

        for result in self.report.results:
            status = "✓ PASS" if result.passed else "✗ FAIL"
            yield Label(f"{result.scenario.title}: {status}", id="scan-result-item")
            yield Label(f"  {result.suggestion}", id="scan-suggestion")
            if result.evidence.canary_triggered:
                yield Label(f"  ⚠ Canary triggered: {result.evidence.canary_found}", id="scan-canary")
            yield Static("")

        yield Label(f"Total: {self.report.total} | Passed: {self.report.passed} | Failed: {self.report.failed}", id="scan-summary")
        yield Label("No guarantee of security. Each defense has limitations.", id="scan-note")
        yield Button("Retest Failed", id="btn-retest-failed", variant="success")
        yield Button("← Back", id="btn-back", variant="default")
