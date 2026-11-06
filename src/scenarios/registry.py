"""Scenario registry — loads and manages scenario definitions."""
from __future__ import annotations

import os
import yaml
from pathlib import Path
from typing import Any, Dict, List
from .base import Scenario


class ScenarioRegistry:
    """Registry of available scenarios."""

    def __init__(self, definitions_dir: str | None = None) -> None:
        self._scenarios: Dict[str, Scenario] = {}
        self._definitions_dir = definitions_dir or self._default_definitions_dir()
        self._load_all()

    def _default_definitions_dir(self) -> str:
        return os.path.join(
            os.path.dirname(__file__),
            "..", "..", "fixtures", "scenarios",
        )

    def _load_all(self) -> None:
        yaml_files = list(Path(self._definitions_dir).glob("*.yaml"))
        if not yaml_files:
            # Use built-in scenarios if no YAML files
            self._load_builtin()
            return

        for filename in sorted(Path(self._definitions_dir).glob("*.yaml")):
            self._load_one(filename)

    def _load_builtin(self) -> None:
        """Load built-in core scenarios."""
        from .definitions import CORE_SCENARIOS
        for scenario in CORE_SCENARIOS:
            self._scenarios[scenario.id] = scenario

    def _load_one(self, path: Path) -> None:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
        scenario = Scenario(**data)
        self._scenarios[scenario.id] = scenario

    def get(self, scenario_id: str) -> Scenario | None:
        return self._scenarios.get(scenario_id)

    def list_all(self) -> List[Scenario]:
        return list(self._scenarios.values())

    def list_core(self) -> List[Scenario]:
        return [s for s in self._scenarios.values() if s.core]

    def list_by_category(self, category: str) -> List[Scenario]:
        return [s for s in self._scenarios.values() if s.category == category]

    def search(self, query: str) -> List[Scenario]:
        query_lower = query.lower()
        return [
            s for s in self._scenarios.values()
            if query_lower in s.id.lower()
            or query_lower in s.title.lower()
            or query_lower in s.category.lower()
        ]
