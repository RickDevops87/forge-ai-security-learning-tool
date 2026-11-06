"""SCAN report formatter — uses scenario-specific evaluators."""
from __future__ import annotations

from typing import Any, Dict, List
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from .runner import ScanReport, ScanResult


class ScanReporter:
    """Formats scan results for display."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, report: ScanReport) -> str:
        """Render the scan report as formatted text."""
        lines: list[str] = []

        lines.append("")
        lines.append("═══ AI SAFETY SCAN — RESULTS ═══")
        lines.append("")

        for result in report.results:
            status = "✓ PASS" if result.passed else "✗ FAIL"
            lines.append(f"  {result.scenario.title}: {status}")
            lines.append(f"    {result.suggestion}")

            # Show scenario-specific evidence
            if hasattr(result, 'evidence') and result.evidence:
                ev = result.evidence
                if "hidden_instruction_detected" in ev:
                    lines.append(f"    Hidden instruction followed: {ev['hidden_instruction_detected']}")
                if "protected_data_exposed" in ev:
                    lines.append(f"    Protected data exposed: {ev['protected_data_exposed']}")
                if "tool_called" in ev:
                    lines.append(f"    Tool called: {ev['tool_called']}")
                if "canaries_found" in ev:
                    lines.append(f"    Canaries found: {ev['canaries_found']}")

            lines.append("")

        # Summary
        lines.append("─" * 60)
        lines.append(f"  Tested: {report.total}  |  Passed: {report.passed}  |  Failed: {report.failed}")
        lines.append("")
        lines.append("  No guarantee of security. Each defense has limitations.")
        lines.append("  'This configuration resisted this tested scenario.'")
        lines.append("")

        return "\n".join(lines)

    def render_scenario_detail(self, result: ScanResult) -> str:
        """Render a single scenario result with evidence."""
        lines = [
            f"Scenario: {result.scenario.title}",
            f"Concept: {result.scenario.description}",
            f"Result: {'PASS' if result.passed else 'FAIL'}",
            f"Evidence: {result.evidence.model_output[:200]}",
            f"Suggestion: {result.suggestion}",
            "",
            "What happened:",
            f"  {result.scenario.what_happens}",
            "",
            "What to watch for:",
            f"  {result.scenario.what_to_watch_for}",
            "",
        ]
        return "\n".join(lines)
