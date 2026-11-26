"""Doctor rules on crafted data."""

import base64
import copy
import hashlib
from typing import Any

import pytest

from astrarium.components.doctor import checks
from astrarium.components.manifest.derive import effective_nodes
from astrarium.components.manifest.models import Manifest
from astrarium.components.topology.bridge import NAMESPACE_PLACEHOLDER, BuiltNode, HexRiftNode


pytestmark = pytest.mark.unit

KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB"

BASE: dict[str, Any] = {
    "deployment": {
        "name": "t",
        "domain": "example.net",
        "names": {"exit": "aphelion", "hub": "perigee"},
    },
    "control": {"jump": "edge", "ssh_allow": ["192.0.2.7"]},
    "nodes": {
        "nlA00": {
            "role": "exit",
            "ipv4": "203.0.113.10",
            "ipv6": "2001:db8::10",
            "host_keys": {"ed25519": KEY},
        },
        "mskA00": {
            "role": "hub",
            "ipv4": "203.0.113.20",
            "host_keys": {"ed25519": KEY},
        },
        "edge": {
            "role": "bastion",
            "ipv4": "198.51.100.20",
            "hostname": "edge.example.net",
            "host_keys": {"ed25519": KEY},
        },
    },
}

HEXRIFT = {
    "nlA00": HexRiftNode(
        "nlA00",
        "nl",
        "exit",
        "nlA00.aphelion.example.net",
    ),
    "mskA00": HexRiftNode(
        "mskA00",
        "msk",
        "hub",
        "mskA00.perigee.example.net",
    ),
}

PYPROJECT = """
[[tool.uv.index]]
name = "photon"
url = "https://photon.example.invalid/simple/"
explicit = true
"""


def lock(source: str) -> str:
    return f'version = 1\n\n[[package]]\nname = "hexrift"\nversion = "0.13.1"\nsource = {{ registry = "{source}" }}\n'


def sshfp(blob: str) -> str:
    return hashlib.sha256(base64.b64decode(blob)).hexdigest()


def build(data=None):
    manifest = Manifest.model_validate(copy.deepcopy(BASE) if data is None else data)
    return manifest, effective_nodes(manifest, {node_id: node.region for node_id, node in HEXRIFT.items()})


def test_node_sets_and_region_types_must_match():
    manifest, nodes = build()
    assert (
        checks.check_node_sets(
            manifest,
            nodes,
            HEXRIFT,
        ).status
        == "pass"
    )
    extra = {
        **HEXRIFT,
        "deA00": HexRiftNode(
            "deA00",
            "de",
            "exit",
            "deA00.aphelion.example.net",
        ),
    }
    assert (
        checks.check_node_sets(
            manifest,
            nodes,
            extra,
        ).status
        == "fail"
    )
    swapped = {
        **HEXRIFT,
        "mskA00": HexRiftNode(
            "mskA00",
            "msk",
            "exit",
            "mskA00.perigee.example.net",
        ),
    }
    assert (
        checks.check_node_sets(
            manifest,
            nodes,
            swapped,
        ).status
        == "fail"
    )


def test_key_files_and_host_keys_are_required():
    data = copy.deepcopy(BASE)
    del data["nodes"]["edge"]["host_keys"]
    _, nodes = build(data)
    assert "mskA00" in checks.check_key_files(nodes, {"nlA00"}).detail
    assert "edge" in checks.check_host_keys(nodes).detail


def test_hostnames_and_aphelion_domain_follow_derived_names():
    manifest, nodes = build()
    assert (
        checks.check_hostnames(
            manifest,
            nodes,
            HEXRIFT,
            "aphelion.example.net",
        ).status
        == "pass"
    )
    wrong = {
        **HEXRIFT,
        "nlA00": HexRiftNode(
            "nlA00",
            "nl",
            "exit",
            "nlA00.example.net",
        ),
    }
    assert (
        checks.check_hostnames(
            manifest,
            nodes,
            wrong,
            "aphelion.example.net",
        ).status
        == "fail"
    )
    assert (
        checks.check_hostnames(
            manifest,
            nodes,
            HEXRIFT,
            "exits.example.net",
        ).status
        == "fail"
    )


def test_jump_needs_host_keys_and_ssh_sources_prevent_lockout():
    data = copy.deepcopy(BASE)
    del data["nodes"]["edge"]["host_keys"]
    manifest, nodes = build(data)
    assert checks.check_jump(manifest, nodes).status == "fail"
    data = copy.deepcopy(BASE)
    data["control"] = {}
    _, nodes = build(data)
    assert checks.check_ssh_sources(nodes).status == "fail"


def test_jump_not_in_empty_fleet_warns_instead_of_crashing():
    manifest = Manifest.model_validate(
        {
            "deployment": BASE["deployment"],
            "control": {"jump": "edge"},
            "nodes": {},
        }
    )
    assert checks.check_jump(manifest, {}).status == "warn"


def test_ssh_sources_rule_without_from_ip_is_not_locked_out():
    data = copy.deepcopy(BASE)
    data["control"] = {}
    data["nodes"]["nlA00"]["overrides"] = {
        "features": {"netsec": {"firewall_rules": [{"port": 22, "action": "allow"}]}}
    }
    data["nodes"]["mskA00"]["overrides"] = {
        "features": {
            "netsec": {
                "firewall_rules": [
                    {
                        "port": 22,
                        "action": "allow",
                        "from_ip": "any",
                    }
                ]
            }
        }
    }
    _, nodes = build(data)
    assert checks.check_ssh_sources(nodes).status == "pass"


def test_haproxy_rendered_where_not_installed_fails():
    data = copy.deepcopy(BASE)
    data["roles"] = {"exit": {"features": {"haproxy": {"install": False}}}}
    _, nodes = build(data)
    built = {
        "nlA00": BuiltNode(
            "nlA00",
            None,  # ty: ignore[invalid-argument-type]
            None,  # ty: ignore[invalid-argument-type]
            True,
        ),
        "mskA00": BuiltNode(
            "mskA00",
            None,  # ty: ignore[invalid-argument-type]
            None,  # ty: ignore[invalid-argument-type]
            True,
        ),
    }
    assert "nlA00" in checks.check_haproxy(nodes, built).detail


def test_photon_packages_must_resolve_from_photon():
    assert checks.check_lockfile(PYPROJECT, lock("https://photon.example.invalid/simple")).status == "pass"
    assert checks.check_lockfile(PYPROJECT, lock("https://pypi.org/simple")).status == "fail"
    assert checks.check_lockfile("[project]\nname = 'x'\n", lock("https://pypi.org/simple")).status == "fail"


def test_dns_records_and_sshfp_must_match_nodes():
    _, nodes = build()
    zone = {
        "nlA00.aphelion": [
            {"type": "A", "value": "203.0.113.10"},
            {"type": "AAAA", "value": "2001:db8::10"},
            {
                "type": "SSHFP",
                "values": [
                    {
                        "algorithm": 4,
                        "fingerprint_type": 2,
                        "fingerprint": sshfp(KEY),
                    }
                ],
            },
        ],
        "mskA00.perigee": {"type": "A", "value": "203.0.113.20"},
        "edge": {"type": "A", "value": "198.51.100.20"},
        "status": {"type": "CNAME", "value": "status.example.org."},
        "_dmarc": {"type": "TXT", "value": "v=DMARC1"},
    }
    records, extra = checks.check_dns(
        zone,
        "example.net",
        nodes,
    )
    assert (records.status, extra.status) == ("pass", "warn")
    assert "status.example.net" in extra.detail
    records, extra = checks.check_dns(
        zone,
        "example.net",
        nodes,
        ignored={"status"},
    )
    assert (records.status, extra.status) == ("pass", "pass")
    assert extra.detail == "none"
    zone["nlA00.aphelion"][2]["values"][0]["fingerprint"] = "00" * 32
    del zone["mskA00.perigee"]
    records, _ = checks.check_dns(
        zone,
        "example.net",
        nodes,
    )
    assert records.status == "fail"
    assert "mskA00" in records.detail and "nlA00" in records.detail


def test_reality_dest_change_of_hub_region_warns():
    committed: dict[str, Any] = {
        "defaults": {"hub": {"reality": {"dest": "www.example.com:443"}}},
        "regions": [
            {
                "id": "msk",
                "type": "hub",
                "nodes": [{"id": "mskA00"}],
            }
        ],
    }
    working = copy.deepcopy(committed)
    assert checks.check_reality_dest(committed, working).status == "pass"
    working["regions"][0]["reality"] = {"dest": "www.example.org:443"}
    assert checks.check_reality_dest(committed, working).status == "warn"


def test_reality_dest_without_committed_topology_is_not_a_pass():
    working: dict[str, Any] = {
        "regions": [
            {
                "id": "msk",
                "type": "hub",
                "nodes": [{"id": "mskA00"}],
            }
        ]
    }
    assert checks.check_reality_dest(None, working).status == "warn"


def test_plaintext_secrets_and_namespace_placement():
    raw = {
        "roles": {"pulsar": {"features": {"telemt": {"users": {"alice": "a" * 32}}}}},
        "features": {"users": {"users": [{"password": ""}]}},
    }
    result = checks.check_plaintext_secrets(raw)
    assert result.status == "fail"
    assert "roles.pulsar.features.telemt.users" in result.detail
    assert checks.check_namespace(NAMESPACE_PLACEHOLDER, "real-ns").status == "pass"
    assert checks.check_namespace("real-ns", "real-ns").status == "fail"
    assert checks.check_namespace(NAMESPACE_PLACEHOLDER, None).status == "fail"


def test_deploy_workflow_without_jump_warns():
    data = copy.deepcopy(BASE)
    data["control"]["jump"] = None
    manifest, _ = build(data)
    assert checks.check_deploy_workflow(True, manifest).status == "warn"
    assert checks.check_deploy_workflow(False, manifest).status == "pass"
