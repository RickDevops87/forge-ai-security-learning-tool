"""Canary detector — identifies synthetic canary strings."""
from __future__ import annotations

CANARY_STRINGS = [
    "THIS_IS_A_CANARY_STRING",
    "CANARY_KEY_DO_NOT_USE",
    "THIS_IS_A_TEST_SECRET",
]


class CanaryDetector:
    """Detects canary strings in model output."""

    def __init__(self) -> None:
        self.triggered_canaries: list[str] = []

    def scan(self, text: str) -> dict:
        """Scan text for canary strings."""
        found = [c for c in CANARY_STRINGS if c in text]
        self.triggered_canaries.extend(found)
        return {
            "triggered": len(found) > 0,
            "canaries_found": found,
            "count": len(found),
        }

    def reset(self) -> None:
        self.triggered_canaries = []

    def get_triggered(self) -> list[str]:
        return self.triggered_canaries.copy()
