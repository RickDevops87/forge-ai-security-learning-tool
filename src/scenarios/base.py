"""Base scenario class."""
from __future__ import annotations

from typing import Any, Dict, List
from pydantic import BaseModel


class Scenario(BaseModel):
    """A single attack/defense scenario definition."""

    id: str
    title: str
    category: str  # attack or defend
    core: bool = True  # part of the 10 core scenarios
    difficulty: str = "beginner"
    description: str
    what_is_this: str
    why_it_matters: str
    what_happens: str
    what_to_watch_for: str
    attack_prompt: str
    attack_tools: List[str] | None = None
    defense_prompt: str | None = None
    defense_principle: str | None = None
    defense_limitations: List[str] | None = None
    success_condition: str = "leak"  # or "refuse", "partial"
    fixtures: List[str] | None = None
    compatible_providers: List[str] | None = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
