"""Secrets overlay allow-list and merge."""

import pytest

from astrarium.components.manifest.overlay import (
    merge_overlay,
    overlay_namespace,
    sensitive_feature_paths,
    validate_overlay,
)
from astrarium.errors import InvalidManifest


pytestmark = pytest.mark.unit

SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_sensitive_paths_come_from_nullforge_molds_including_union_members():
    assert {
        "telemt.users",
        "users.users",
        "monitoring.backend.client_secret",
        "monitoring.backend.api_token",
        "zerotrust.token",
    } <= sensitive_feature_paths()


def test_overlay_accepts_secrets_at_every_feature_layer():
    validate_overlay(
        {
            "topology": {"namespace": "real-namespace"},
            "notify": {"discord": {"webhook_url": "https://discord.example.invalid/x", "thread_id": "1"}},
            "features": {"monitoring": {"backend": {"client_secret": "s", "api_token": "t"}}},
            "roles": {"pulsar": {"features": {"telemt": {"users": {"alice": SECRET}}}}},
            "nodes": {"edge": {"overrides": {"features": {"users": {"users": [{"password": "x"}]}}}}},
            "sops": {"version": "3.13.3"},
        }
    )


@pytest.mark.parametrize(
    "overlay",
    [
        {"control": {"deploy_keys": ["ssh-ed25519 AAAA attacker"]}},
        {"control": {"ssh_allow": ["0.0.0.0/0"]}},
        {"nodes": {"nlA00": {"host_keys": {"ed25519": "AAAA"}}}},
        {"nodes": {"nlA00": {"ipv4": "192.0.2.66"}}},
        {"versions": {"xray": "main@" + "0" * 40}},
        {"roles": {"pulsar": {"features": {"telemt": {"port": 8443}}}}},
        {"roles": {"pulsar": {"features": {"telemt": {"users_extra": {"x": SECRET}}}}}},
        {"features": {"netsec": {"firewall_rules": []}}},
        {"topology": {"aphelion_domain": "evil.example"}},
    ],
)
def test_overlay_rejects_paths_outside_allow_list(overlay):
    with pytest.raises(InvalidManifest):
        validate_overlay(overlay)


def test_merge_overlay_ignores_empty_mapping_at_non_allowed_path():
    raw = {"roles": {"pulsar": {"features": {"telemt": {"tls_domain": "www.example.org"}}}}}
    merged = merge_overlay(raw, {"control": {"ci": {}}})
    assert merged == raw


def test_merge_overlay_adds_secrets_path_by_path_and_drops_topology():
    raw = {"roles": {"pulsar": {"features": {"telemt": {"tls_domain": "www.example.org"}}}}}
    overlay = {
        "topology": {"namespace": "ns"},
        "roles": {"pulsar": {"features": {"telemt": {"users": {"alice": SECRET}}}}},
    }
    merged = merge_overlay(raw, overlay)
    assert merged == {
        "roles": {"pulsar": {"features": {"telemt": {"tls_domain": "www.example.org", "users": {"alice": SECRET}}}}}
    }
    assert overlay_namespace(overlay) == "ns"
    assert overlay_namespace({}) is None
