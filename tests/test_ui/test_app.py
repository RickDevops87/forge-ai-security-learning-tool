import json

import pytest
from textual.widgets import Button

from src.ui.app import SecurityLabApp


@pytest.mark.asyncio
async def test_learn_navigation_mounts_scenarios_and_attack_evidence(tmp_path):
    app = SecurityLabApp(str(tmp_path / "progress.json"))
    async with app.run_test(size=(120, 50)) as pilot:
        await pilot.click("#btn-learn")
        assert app.query_one("#scenario-PI-01")

        app.query_one("#scenario-PI-01", Button).press()
        await pilot.pause()
        assert "PI-01" in str(app.query_one("#title").render())

        app.query_one("#btn-attack", Button).press()
        await pilot.pause(0.6)
        assert "Attack evidence" in str(app.query_one("#title").render())
        assert app._attack_result is not None
        assert app._attack_result.scenario_id == "PI-01"


@pytest.mark.asyncio
async def test_human_attack_defense_review_is_required_and_persisted(tmp_path):
    progress_path = tmp_path / "progress.json"
    app = SecurityLabApp(str(progress_path))
    async with app.run_test(size=(120, 60)) as pilot:
        await app._show_exercise("RP-01")
        await app._do_attack()
        await app._record_verdict("attack-observed")
        await app._do_defense()
        await app._record_verdict("defense-effective")
        app.query_one("#review-notes").text = "Poison reached retrieval; defended output flagged it."
        await app._save_review()

        assert progress_path.exists()
        saved = json.loads(progress_path.read_text())
        assert saved["RP-01"]["completed"] is True
        assert "attack-observed" not in saved["RP-01"]["notes"]
        notes = json.loads(saved["RP-01"]["notes"])
        assert notes["human_verdicts"] == {
            "attack": "observed",
            "defense": "effective",
        }
        assert "Poison reached retrieval" in notes["notes"]


@pytest.mark.asyncio
async def test_scan_renders_inconclusive_separately(tmp_path):
    app = SecurityLabApp(str(tmp_path / "progress.json"))
    async with app.run_test(size=(120, 50)):
        await app._do_scan()
        rendered = " ".join(str(widget.render()) for widget in app.query("Label"))
        assert "Inconclusive" in rendered
        assert "Failed" in rendered
