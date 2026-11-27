"""pyinfra host data per node."""

import copy
from pathlib import Path

import pytest

from astrarium.components.inventory.render import host_data
from astrarium.components.sshcfg.render import SshPaths
from tests.support.fleet import fleet, make_control


pytestmark = pytest.mark.unit


def _ssh(identity, nodes):
    return SshPaths(
        config=Path("/run/astrarium/ssh_config"),
        known_hosts=Path("/run/astrarium/known_hosts"),
        identity=identity,
        via="jump",
        nodes=frozenset(nodes),
    )


def test_ci_casts_never_copy_login_keys_into_managed_admin():
    nodes = fleet()
    node = nodes["nlA00"]
    before = copy.deepcopy(node.features)
    ci = host_data(
        node,
        nodes,
        _ssh("ci", nodes),
        make_control(),
    )
    entries = ci["features"]["users"]["users"]
    assert entries and all(entry["copy_root_keys"] is False for entry in entries)
    assert node.features == before


def test_fleet_nodes_get_deploy_user_as_deploy_role_entry():
    nodes = fleet()
    node = nodes["nlA00"]
    control = make_control()
    data = host_data(
        node,
        nodes,
        _ssh("admin", nodes),
        control,
    )
    entries = data["features"]["users"]["users"]
    deploy = next(entry for entry in entries if entry["name"] == control.deploy_user)
    assert deploy["role"] == "deploy"
    assert deploy["sudo_commands"]
    assert deploy["ssh_keys"] == list(control.deploy_keys)


def test_bastion_gets_no_deploy_user_entry():
    nodes = fleet()
    edge = nodes["edge"]
    data = host_data(
        edge,
        nodes,
        _ssh("admin", nodes),
        make_control(),
    )
    names = [entry["name"] for entry in data["features"]["users"]["users"]]
    assert make_control().deploy_user not in names
