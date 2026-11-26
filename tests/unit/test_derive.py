"""Effective nodes: layering order, derived names, generated rules, validation."""

import copy
from typing import Any

import pytest
from nullforge.smithy.versions import DEFAULT_VERSIONS

from astrarium.components.manifest.derive import effective_nodes
from astrarium.components.manifest.models import Manifest
from astrarium.errors import InvalidManifest


pytestmark = pytest.mark.unit

SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

BASE: dict[str, Any] = {
    "deployment": {
        "name": "t",
        "domain": "example.net",
        "names": {
            "exit": "aphelion",
            "hub": "perigee",
            "pulsar": "pulsar",
        },
    },
    "control": {"jump": "edge", "ssh_allow": [{"source": "192.0.2.7", "comment": "Home SSH"}]},
    "roles": {"pulsar": {"features": {"telemt": {"tls_domain": "www.example.org", "users": {"alice": SECRET}}}}},
    "nodes": {
        "nlA00": {"role": "exit", "ipv4": "203.0.113.10"},
        "mskA00": {"role": "hub", "ipv4": "203.0.113.20"},
        "mskP00": {"role": "pulsar", "ipv4": "203.0.113.30"},
        "edge": {
            "role": "bastion",
            "ipv4": "198.51.100.20",
            "hostname": "edge.fleet",
            "ssh": {"port": 22443, "user": "operator"},
        },
    },
}

REGIONS = {"nlA00": "nl", "mskA00": "moscow"}


def rules_of(node):
    return [
        (
            rule["port"],
            rule["from_ip"],
            rule["comment"],
        )
        for rule in node.features["netsec"]["firewall_rules"]
    ]


def nodes(**changes):
    data = copy.deepcopy(BASE)
    for key, value in changes.items():
        data[key] = value
    return effective_nodes(Manifest.model_validate(data), REGIONS)


def test_layers_apply_preset_global_role_node_in_order():
    data = copy.deepcopy(BASE)
    data["features"] = {"dns": {"ecs": False}, "profiles": {"for_root": False}}
    data["roles"]["exit"] = {"features": {"dns": {"ecs": True}}}
    data["nodes"]["nlA00"]["overrides"] = {"features": {"profiles": {"for_root": True}}}
    node = effective_nodes(Manifest.model_validate(data), REGIONS)["nlA00"]
    assert node.features["dns"]["mode"] == "blocky"
    assert node.features["dns"]["ecs"] is True
    assert node.features["profiles"]["for_root"] is True
    assert node.provenance["features.dns.mode"] == "preset:exit"
    assert node.provenance["features.dns.ecs"] == "role:exit"
    assert node.provenance["features.profiles.for_root"] == "node:nlA00"


def test_custom_role_follows_root_preset_and_hexrift_membership():
    data = copy.deepcopy(BASE)
    data["roles"]["relay"] = {
        "extends": "hub",
        "features": {"warp": {"install": False}},
        "runes": ["extra"],
    }
    data["nodes"]["mskA00"]["role"] = "relay"
    node = effective_nodes(Manifest.model_validate(data), REGIONS)["mskA00"]
    assert (
        node.role,
        node.root_role,
        node.is_hexrift,
    ) == (
        "relay",
        "hub",
        True,
    )
    assert node.features["xray"]["install"] is True
    assert node.features["warp"]["install"] is False
    assert node.fqdn == "mskA00.perigee.example.net"
    assert node.runes == ["extra"]


def test_generated_ssh_rules_survive_list_replacement():
    data = copy.deepcopy(BASE)
    data["nodes"]["nlA00"]["overrides"] = {
        "features": {"netsec": {"firewall_rules": [{"port": 8443, "comment": "Alt"}]}}
    }
    node = effective_nodes(Manifest.model_validate(data), REGIONS)["nlA00"]
    assert rules_of(node) == [
        (
            8443,
            None,
            "Alt",
        ),
        (
            22,
            "192.0.2.7",
            "Home SSH",
        ),
        (
            22,
            "198.51.100.20",
            "edge jump SSH",
        ),
    ]


def test_bastion_ssh_rule_follows_its_ssh_port():
    assert (
        22443,
        None,
        "SSH",
    ) in rules_of(nodes()["edge"])
    assert all(from_ip is None for _, from_ip, _ in rules_of(nodes()["edge"]))


def test_regions_come_from_hexrift_for_hub_exit_and_from_id_otherwise():
    result = nodes()
    assert result["mskA00"].region == "moscow"
    assert result["mskP00"].region == "msk"
    assert result["edge"].region == "edge"


def test_names_follow_domain_labels_and_overrides():
    result = nodes()
    assert result["nlA00"].fqdn == "nlA00.aphelion.example.net"
    assert result["edge"].fqdn == "edge.example.net"
    assert result["edge"].system_hostname == "edge.fleet"
    assert result["mskP00"].system_hostname == "mskP00.pulsar"


def test_system_hostname_is_derived_and_in_system_dump():
    data = copy.deepcopy(BASE)
    data["system"] = {"timezone": "Europe/Amsterdam"}
    node = effective_nodes(Manifest.model_validate(data), REGIONS)["nlA00"]
    assert node.system["hostname"] == "nlA00.aphelion" == node.system_hostname
    assert node.system["timezone"] == "Europe/Amsterdam"


@pytest.mark.parametrize(
    "place",
    [
        ("system",),
        (
            "roles",
            "pulsar",
            "system",
        ),
        (
            "nodes",
            "mskP00",
            "overrides",
            "system",
        ),
    ],
)
def test_system_hostname_at_any_layer_is_invalid(place: tuple[str, ...]):
    data = copy.deepcopy(BASE)
    target = data
    for key in place:
        target = target.setdefault(key, {})
    target["hostname"] = "custom.example.net"
    with pytest.raises(InvalidManifest):
        effective_nodes(Manifest.model_validate(data), REGIONS)


def test_hostname_without_dot_leaves_nullforge_hostname_unset():
    data = copy.deepcopy(BASE)
    del data["nodes"]["edge"]["hostname"]
    node = effective_nodes(Manifest.model_validate(data), REGIONS)["edge"]
    assert node.system_hostname == "edge"
    assert node.system["hostname"] is None


def test_versions_layer_nullforge_defaults_manifest_then_node():
    data = copy.deepcopy(BASE)
    data["versions"] = {"telemt": "3.5.7", "blocky": "v0.35.0"}
    data["nodes"]["mskP00"]["overrides"] = {"versions": {"telemt": "3.5.8"}}
    result = effective_nodes(Manifest.model_validate(data), REGIONS)
    assert result["mskP00"].versions["telemt"] == "3.5.8"
    assert result["nlA00"].versions["telemt"] == "3.5.7"
    assert result["nlA00"].versions["wgcf"] == DEFAULT_VERSIONS["wgcf"]
    assert result["mskP00"].provenance["versions.telemt"] == "node"


def test_admin_user_is_managed_user_name_only():
    data = copy.deepcopy(BASE)
    data["nodes"]["nlA00"]["overrides"] = {"features": {"users": {"users": [{"name": "admin", "role": "admin"}]}}}
    result = effective_nodes(Manifest.model_validate(data), REGIONS)
    assert result["nlA00"].admin_user == "admin"
    assert result["edge"].admin_user is None
    assert result["edge"].ssh_user == "operator"


def test_layers_valid_only_in_combination_pass_final_validation():
    data = copy.deepcopy(BASE)
    data["roles"]["pulsar"] = {"features": {"telemt": {"tls_domain": "www.example.org"}}}
    data["nodes"]["mskP00"]["overrides"] = {"features": {"telemt": {"users": {"alice": SECRET}}}}
    assert effective_nodes(Manifest.model_validate(data), REGIONS)["mskP00"].features["telemt"]["users"] == {
        "alice": SECRET
    }


def test_validation_errors_name_node_and_field_but_never_values():
    data = copy.deepcopy(BASE)
    data["roles"]["pulsar"]["features"]["telemt"]["users"] = {"alice": "not-hex-but-secret-value"}
    data["nodes"]["nlA00"]["overrides"] = {"features": {"dns": {"mood": "blocky"}}}
    with pytest.raises(InvalidManifest) as caught:
        effective_nodes(Manifest.model_validate(data), REGIONS)
    message = caught.value.message
    assert "mskP00" in message and "features.telemt" in message
    assert "nlA00" in message and "features.dns.mood" in message
    assert "not-hex-but-secret-value" not in message
