"""Built-in presets and role chains."""

import pytest
from nullforge.molds import FeaturesMold

from astrarium.components.manifest.layering import deep_merge
from astrarium.components.manifest.models import BUILTIN_ROLES, Manifest
from astrarium.components.manifest.presets import load_preset, role_chain, root_role
from astrarium.errors import InvalidManifest


pytestmark = pytest.mark.unit

DEPLOYMENT_PARTS = {
    "pulsar": {"telemt": {"tls_domain": "www.example.org", "users": {"alice": "a1b2c3d4e5f60718293a4b5c6d7e8f90"}}},
}


def _manifest(roles: dict) -> Manifest:
    return Manifest.model_validate(
        {
            "deployment": {"name": "t"},
            "roles": roles,
            "nodes": {"a": {"role": "exit", "ipv4": "203.0.113.1"}},
        }
    )


@pytest.mark.parametrize("role", BUILTIN_ROLES)
def test_presets_validate_once_deployment_parts_are_added(role):
    preset = load_preset(role)
    assert set(preset) == {"system", "features"}
    features = deep_merge(preset["features"], DEPLOYMENT_PARTS.get(role, {}))
    for rule in features["netsec"]["firewall_rules"]:
        if rule.get("port") == "ssh":
            rule["port"] = 22
    FeaturesMold.model_validate(features)


def test_unknown_preset_is_invalid():
    with pytest.raises(InvalidManifest):
        load_preset("relay")


def test_role_chain_lists_root_first():
    manifest = _manifest({"relay": {"extends": "hub"}, "edge-relay": {"extends": "relay"}})
    assert role_chain(manifest, "edge-relay") == [
        "hub",
        "relay",
        "edge-relay",
    ]
    assert root_role(manifest, "edge-relay") == "hub"
    assert role_chain(manifest, "exit") == ["exit"]


@pytest.mark.parametrize(
    "roles",
    [
        {"a-role": {"extends": "b-role"}, "b-role": {"extends": "a-role"}},
        {"hub": {"extends": "exit"}},
        {"relay": {"extends": "relay"}},
    ],
)
def test_cycles_and_builtin_extends_are_invalid(roles):
    manifest = _manifest(roles)
    with pytest.raises(InvalidManifest):
        role_chain(manifest, next(iter(roles)))
