"""Progress tracking — local JSON store."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel


class ScenarioProgress(BaseModel):
    scenario_id: str
    completed: bool = False
    attack_result: Dict[str, Any] | None = None
    defense_result: Dict[str, Any] | None = None
    retest_result: Dict[str, Any] | None = None
    notes: str = ""


class ProgressTracker:
    """Tracks user progress across scenarios."""

    def __init__(self, storage_path: str = "~/.ai-security-lab/progress.json") -> None:
        self.storage_path = Path(storage_path).expanduser()
        self._progress: Dict[str, ScenarioProgress] = {}
        self._load()

    def _load(self) -> None:
        if self.storage_path.exists():
            data = json.loads(self.storage_path.read_text())
            self._progress = {
                k: ScenarioProgress(**v) for k, v in data.items()
            }

    def save(self) -> None:
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        data = {k: v.model_dump() for k, v in self._progress.items()}
        self.storage_path.write_text(json.dumps(data, indent=2))

    def get(self, scenario_id: str) -> ScenarioProgress:
        if scenario_id not in self._progress:
            self._progress[scenario_id] = ScenarioProgress(scenario_id=scenario_id)
        return self._progress[scenario_id]

    def mark_complete(self, scenario_id: str, attack_result: Dict, defense_result: Dict | None = None, retest_result: Dict | None = None) -> None:
        progress = self.get(scenario_id)
        progress.completed = True
        progress.attack_result = attack_result
        if defense_result:
            progress.defense_result = defense_result
        if retest_result:
            progress.retest_result = retest_result
        self.save()

    def completed_count(self) -> int:
        return sum(1 for p in self._progress.values() if p.completed)

    def total_count(self) -> int:
        return len(self._progress)
