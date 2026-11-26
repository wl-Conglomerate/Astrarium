"""Manifest model contracts: typos fail, references resolve, pins take documented shapes."""

import pytest
from pydantic import ValidationError

from astrarium.components.manifest.models import Manifest, XrayRelease


pytestmark = pytest.mark.unit

SHA = "0123456789abcdef0123456789abcdef01234567"


def manifest(**sections) -> dict:
    data = {
        "deployment": {"name": "test", "domain": "example.net"},
        "nodes": {"nlA00": {"role": "exit", "ipv4": "203.0.113.10"}},
    }
    data.update(sections)
    return data


def test_minimal_manifest_gets_documented_defaults():
    model = Manifest.model_validate(manifest())
    assert model.control.deploy_user == "github_actions"
    assert model.keys.exit_rotation == "manual"
    assert model.nodes["nlA00"].arch == "x86_64"
    assert model.nodes["nlA00"].ssh.port == 22


@pytest.mark.parametrize(
    "broken",
    [
        {"deployment": {"name": "test", "domian": "example.net"}},
        {
            "nodes": {
                "nlA00": {
                    "role": "exit",
                    "ipv4": "203.0.113.10",
                    "hostkeys": {},
                }
            }
        },
        {"nodes": {"nl*00": {"role": "exit", "ipv4": "203.0.113.10"}}},
        {"nodes": {"nlA00": {"role": "exit", "ipv4": "2001:db8::10"}}},
        {
            "nodes": {
                "nlA00": {
                    "role": "exit",
                    "ipv4": "203.0.113.10",
                    "host_keys": {"ed25519": "ssh-ed25519 AAAA"},
                }
            }
        },
        {
            "nodes": {
                "nlA00": {
                    "role": "exit",
                    "ipv4": "203.0.113.10",
                    "host_keys": {"ed25519": ""},
                }
            }
        },
    ],
)
def test_typos_bad_ids_and_bad_addresses_fail(broken):
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(**broken))


@pytest.mark.parametrize(
    "broken",
    [
        {"nodes": {"nlA00": {"role": "relay", "ipv4": "203.0.113.10"}}},
        {"roles": {"relay": {}}},
        {"roles": {"relay": {"extends": "nowhere"}}},
        {"control": {"jump": "edge"}},
        {"control": {"orrery": {"host": "edge", "topology_path": "/srv/topology.yaml"}}},
    ],
)
def test_references_to_unknown_roles_and_nodes_fail(broken):
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(**broken))


@pytest.mark.parametrize(
    "broken",
    [
        {"control": {"deploy_user": "a" * 33}},
        {"control": {"ci": {"cast_user": "a" * 33}}},
        {
            "nodes": {
                "nlA00": {
                    "role": "exit",
                    "ipv4": "203.0.113.10",
                    "ssh": {"user": "a" * 33},
                }
            }
        },
    ],
)
def test_account_names_over_32_chars_fail(broken):
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(**broken))


def test_version_pins_take_documented_shapes():
    model = Manifest.model_validate(
        manifest(versions={"xray": {"version": "v26.3.27", "sha256": {"x86_64": "a" * 64}}, "telemt": "3.5.7"})
    )
    assert isinstance(model.versions["xray"], XrayRelease)
    assert Manifest.model_validate(manifest(versions={"xray": f"main@{SHA}"})).versions["xray"] == f"main@{SHA}"


@pytest.mark.parametrize(
    "versions",
    [
        {"xray": "v26.3.27"},
        {"xray": "main@abc"},
        {"telemt": {"version": "v1.0.0", "sha256": {"x86_64": "a" * 64}}},
        {"xray": {"version": "v26.3.27", "sha256": {"x86_64": "not-hex"}}},
    ],
)
def test_malformed_pins_fail(versions):
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(versions=versions))


def test_control_jump_tolerated_while_fleet_has_no_nodes():
    model = Manifest.model_validate(manifest(nodes={}, control={"jump": "edge"}))
    assert model.control.jump == "edge"


def test_ssh_allow_accepts_strings_and_commented_entries():
    model = Manifest.model_validate(
        manifest(control={"ssh_allow": ["192.0.2.7", {"source": "2001:db8::/32", "comment": "Office"}]})
    )
    assert len(model.control.ssh_allow) == 2


def test_ci_cast_user_same_as_deploy_user_fails():
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(control={"ci": {"cast_user": "github_actions"}}))


def test_key_in_both_deploy_keys_and_ci_cast_keys_fails():
    key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdjfJU6wRLEqMViaQxqQDVG30ws3gV5M432EnmEOSfb"
    control = {"deploy_keys": [f"no-pty {key} laptop"], "ci": {"cast_keys": [f"{key} ci"]}}
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(control=control))


def test_bad_rune_name_fails():
    with pytest.raises(ValidationError):
        Manifest.model_validate(manifest(roles={"relay": {"extends": "exit", "runes": ["My-Rune"]}}))


def test_discord_thread_id_accepts_unquoted_number():
    model = Manifest.model_validate(manifest(notify={"discord": {"thread_id": 1234567890123456789}}))
    assert model.notify.discord is not None
    assert model.notify.discord.thread_id == "1234567890123456789"
