"""agent_min_confidence is picked from fixed levels in the console, but the backend stays strict (0..1).

The selectable levels live in frontend/src/lib/confidenceLevels.ts; this test reads that file so the backend
check and the UI list cannot drift apart. Rationale: docs/CONFIDENCE_LEVEL.md.
"""
import re
from pathlib import Path

import pytest

from backend import integration_config
from backend.routers import config as config_router
from backend.tests.ws6_helpers import _clean_state, admin_h  # noqa: F401

LEVELS_TS = Path(__file__).resolve().parents[2] / "frontend" / "src" / "lib" / "confidenceLevels.ts"


def _ui_default(text=None):
    text = text or LEVELS_TS.read_text(encoding="utf-8")
    return re.search(r'export const DEFAULT_CONFIDENCE = "([0-9.]+)"', text).group(1)


def _ui_levels():
    text = LEVELS_TS.read_text(encoding="utf-8")
    values = set(re.findall(r'\{ value: "([0-9.]+)", name: "', text))
    if re.search(r'\{ value: DEFAULT_CONFIDENCE, name: "', text):
        values.add(_ui_default(text))
    return sorted(values, key=float)


def save(client, headers, value):
    return client.post("/api/configuration", headers=headers, json={"configs": [
        {"category": "AGENT", "key_name": "agent_min_confidence", "key_value": value, "clear": value == ""}]})


@pytest.fixture(autouse=True)
def _reset(client, admin_h):
    yield
    save(client, admin_h, "")


def test_ui_list_has_the_expected_shape_and_default():
    levels = _ui_levels()
    assert len(levels) >= 6
    assert _ui_default() == integration_config.DEFAULTS["agent_min_confidence"] == "0.85"
    assert _ui_default() in levels
    assert all(0.0 < float(v) <= 1.0 for v in levels)
    # Canonical form: what the backend stores for the value is the value itself.
    assert all(str(float(v)) == v for v in levels)


def test_every_listed_level_is_accepted_and_stored_unchanged(client, admin_h):
    for value in _ui_levels():
        assert config_router._validate_value("agent_min_confidence", value) == (value, None)
        res = save(client, admin_h, value)
        assert res.status_code == 200, (value, res.text)
        entry = client.get("/api/configuration", headers=admin_h).json()["AGENT"]["agent_min_confidence"]
        assert entry["value"] == value
        # The policy engine and the agent status read exactly this number.
        assert float(integration_config.get_setting("agent_min_confidence")) == float(value)


@pytest.mark.parametrize("bad", ["1.5", "-0.1", "2", "abc", "0,9", "90%", "nan", "inf", "-inf", "1e3", "0.85abc"])
def test_out_of_range_or_non_numeric_values_are_still_rejected(client, admin_h, bad):
    value, error = config_router._validate_value("agent_min_confidence", bad)
    assert error is not None
    res = save(client, admin_h, bad)
    assert res.status_code == 400, (bad, res.text)


@pytest.mark.parametrize("edge", ["0", "0.0", "1", "1.0", "0.87"])
def test_unlisted_but_valid_numbers_remain_valid_for_api_and_environment_users(edge):
    # A stored "Custom (xx%)" value must keep working; the UI only stops people typing, not the API contract.
    assert config_router._validate_value("agent_min_confidence", edge)[1] is None


def test_spelling_variants_are_normalised_to_the_listed_value(client, admin_h):
    assert config_router._validate_value("agent_min_confidence", "0.90") == ("0.9", None)
    res = save(client, admin_h, "0.90")
    assert res.status_code == 200
    assert client.get("/api/configuration", headers=admin_h).json()["AGENT"]["agent_min_confidence"]["value"] == "0.9"


def test_default_is_used_when_the_setting_is_cleared(client, admin_h):
    assert save(client, admin_h, "0.95").status_code == 200
    assert save(client, admin_h, "").status_code == 200
    entry = client.get("/api/configuration", headers=admin_h).json()["AGENT"]["agent_min_confidence"]
    assert entry["value"] == "0.85"
