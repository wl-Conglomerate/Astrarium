"""Generated pyinfra inventory module."""

import re
import runpy
import stat
from dataclasses import replace

import pytest

from astrarium.components.inventory.access import fleet_endpoints
from astrarium.components.inventory.render import INVENTORY_FILENAME, render_inventory, write_inventory
from astrarium.components.manifest.models import NODE_ID_PATTERN
from astrarium.components.sshcfg.render import SshPaths
from astrarium.errors import AstrariumError, InvalidManifest
from astrarium.runtime import RuntimeDir
from tests.support.fleet import fleet, make_control


pytestmark = pytest.mark.component


def _ssh(tmp_path, nodes):
    config = tmp_path / "ssh_config"
    config.write_text("Host *\n", encoding="utf-8")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("", encoding="utf-8")
    return SshPaths(
        config=config,
        known_hosts=known_hosts,
        identity="admin",
        via="jump",
        nodes=frozenset(nodes),
    )


def _load(tmp_path, text):
    path = tmp_path / INVENTORY_FILENAME
    path.write_text(text, encoding="utf-8")
    module = runpy.run_path(str(path))
    return {name: value for name, value in module.items() if not name.startswith("_") and isinstance(value, list)}


def test_inventory_module_groups_hosts_by_root_role(tmp_path):
    nodes = fleet()
    groups = _load(
        tmp_path,
        render_inventory(
            nodes,
            nodes,
            _ssh(tmp_path, nodes),
            make_control(),
        ),
    )
    assert set(groups) == {
        "bastion",
        "exit",
        "hub",
        "pulsar",
    }
    assert sorted(name for name, _ in groups["exit"]) == ["nlA00", "nlA01"]
    assert all(isinstance(host, tuple) for hosts in groups.values() for host in hosts)


def test_host_data_carries_ssh_files_login_and_nullforge_pins_only(tmp_path):
    nodes = fleet()
    nodes["nlA00"] = replace(
        nodes["nlA00"],
        versions={
            **nodes["nlA00"].versions,
            "xray": "main@" + "a" * 40,
            "telemt": "3.5.7",
        },
    )
    ssh = _ssh(tmp_path, nodes)
    data = dict(
        _load(
            tmp_path,
            render_inventory(
                nodes,
                nodes,
                ssh,
                make_control(),
            ),
        )["exit"]
    )["nlA00"]
    assert data["ssh_config_file"] == str(ssh.config)
    assert data["ssh_known_hosts_file"] == str(ssh.known_hosts)
    assert data["ssh_strict_host_key_checking"] == "yes"
    assert data["ssh_user"] == "core"
    assert data["zone"] == "exit"
    assert "xray" not in data["versions"]
    assert data["versions"]["telemt"] == "3.5.7"
    assert data["astrarium"]["deploy_user"] == "github_actions"


def test_profiles_cover_admin_and_root_but_not_deploy(tmp_path):
    nodes = fleet()
    ssh = _ssh(tmp_path, nodes)
    data = dict(
        _load(
            tmp_path,
            render_inventory(
                nodes,
                nodes,
                ssh,
                make_control(),
            ),
        )["exit"]
    )["nlA00"]
    profiles = data["features"]["profiles"]
    assert profiles["for_root"] is True
    assert profiles["users"] == ["core"]
    users = {entry["name"]: entry for entry in data["features"]["users"]["users"]}
    assert users["github_actions"]["shell"] == "/bin/bash"
    assert users["core"]["shell"] == "/bin/zsh"


def test_inventory_refuses_missing_ssh_config(tmp_path):
    nodes = fleet()
    ssh = _ssh(tmp_path, nodes)
    ssh.config.unlink()
    with pytest.raises(AstrariumError):
        render_inventory(
            nodes,
            nodes,
            ssh,
            make_control(),
        )


def test_bastion_only_target_still_permits_every_non_bastion_fleet_endpoint(tmp_path):
    full = fleet()
    targets = {"edge": full["edge"]}
    ssh = _ssh(tmp_path, targets)
    data = dict(
        _load(
            tmp_path,
            render_inventory(
                targets,
                full,
                ssh,
                make_control(),
            ),
        )["bastion"]
    )["edge"]
    permitted = {
        endpoint for line in data["astrarium"]["deploy_keys"] for endpoint in re.findall(r'permitopen="([^"]+)"', line)
    }
    assert permitted == set(fleet_endpoints(full))


def test_exit_only_targets_with_ci_cast_keys_render_without_error(tmp_path):
    full = fleet()
    targets = {node_id: node for node_id, node in full.items() if node.root_role == "exit"}
    ssh = _ssh(tmp_path, {**targets, "edge": full["edge"]})
    groups = _load(
        tmp_path,
        render_inventory(
            targets,
            full,
            ssh,
            make_control(),
        ),
    )
    assert set(groups) == {"exit"}
    assert dict(groups["exit"])["nlA00"]["astrarium"]["ci_cast_keys"]


def test_target_outside_ssh_scope_raises_invalid_manifest(tmp_path):
    full = fleet()
    ssh = _ssh(tmp_path, {"edge": full["edge"]})
    with pytest.raises(InvalidManifest):
        render_inventory(
            full,
            full,
            ssh,
            make_control(),
        )


def test_written_inventory_is_private_and_its_group_cannot_match_a_node():
    with RuntimeDir() as runtime:
        path = write_inventory(runtime, "exit = []\n")
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert re.fullmatch(NODE_ID_PATTERN, path.stem) is None
