"""Plain-dict layering and provenance."""

import pytest

from astrarium.components.manifest.layering import deep_merge, merge_with_provenance


pytestmark = pytest.mark.unit


def test_dicts_merge_and_lists_replace_without_touching_inputs():
    base = {"netsec": {"firewall": True, "firewall_rules": [{"port": 443}]}, "dns": {"mode": "blocky"}}
    layer = {"netsec": {"firewall_rules": [{"port": 8443}]}, "dns": {"ecs": True}}
    merged = deep_merge(base, layer)
    assert merged == {
        "netsec": {"firewall": True, "firewall_rules": [{"port": 8443}]},
        "dns": {"mode": "blocky", "ecs": True},
    }
    assert base["netsec"]["firewall_rules"] == [{"port": 443}]
    merged["dns"]["mode"] = "none"
    assert base["dns"]["mode"] == "blocky"


def test_scalar_replaces_dict_and_dict_replaces_scalar():
    assert deep_merge({"a": {"b": 1}}, {"a": 2}) == {"a": 2}
    assert deep_merge({"a": 2}, {"a": {"b": 1}}) == {"a": {"b": 1}}


def test_provenance_names_last_layer_per_leaf():
    merged, provenance = merge_with_provenance(
        [
            ("preset:exit", {"features": {"dns": {"mode": "blocky", "ecs": True}, "warp": {"install": True}}}),
            ("manifest", {"features": {}}),
            ("role:exit", {"features": {"dns": {"ecs": False}}}),
            ("node:nlA00", {"features": {"warp": False}}),
        ]
    )
    assert merged["features"] == {"dns": {"mode": "blocky", "ecs": False}, "warp": False}
    assert provenance == {
        "features.dns.mode": "preset:exit",
        "features.dns.ecs": "role:exit",
        "features.warp": "node:nlA00",
    }


def test_empty_dict_replacing_scalar_drops_stale_provenance():
    merged, provenance = merge_with_provenance(
        [
            ("A", {"f": {"warp": False}}),
            ("B", {"f": {"warp": {}}}),
        ]
    )
    assert merged == {"f": {"warp": {}}}
    assert provenance == {}
