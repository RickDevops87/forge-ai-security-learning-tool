import pytest
from src.scenarios.registry import ScenarioRegistry
from src.scenarios.base import Scenario


def test_registry_loads_core_scenarios():
    registry = ScenarioRegistry()
    core = registry.list_core()
    assert len(core) == 10
    for scenario in core:
        assert scenario.core is True
        assert scenario.attack_prompt is not None
        assert scenario.description is not None


def test_registry_get_by_id():
    registry = ScenarioRegistry()
    scenario = registry.get("PI-01")
    assert scenario is not None
    assert scenario.id == "PI-01"
    assert scenario.title == "Hidden Instructions"


def test_registry_search():
    registry = ScenarioRegistry()
    results = registry.search("hidden")
    assert len(results) > 0
    for r in results:
        assert "hidden" in r.id.lower() or "hidden" in r.title.lower()


def test_all_core_scenarios_have_defense():
    registry = ScenarioRegistry()
    core = registry.list_core()
    for scenario in core:
        assert scenario.defense_prompt is not None, f"{scenario.id} missing defense_prompt"
        assert scenario.defense_principle is not None, f"{scenario.id} missing defense_principle"