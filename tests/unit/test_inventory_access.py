"""Authorized key lines and access host data for deploy_access and ci_access runes."""

import pytest

from astrarium.components.inventory.access import access_data, ci_line, jump_only_line
from astrarium.components.manifest.keylines import split_key_line, split_options
from astrarium.components.manifest.models import CiControl
from astrarium.errors import InvalidManifest
from tests.support.fleet import CI_KEY, OPERATOR_KEY, fleet, make_control


pytestmark = pytest.mark.unit

REBUILDERS = {
    "hop": lambda line: jump_only_line(line, ["203.0.113.10:22"]),
    "ci": lambda line: ci_line(line, ["198.51.100.20"]),
}


def test_split_key_line_keeps_quoted_commas_and_spaces_in_options():
    options, key = split_key_line(f'from="203.0.113.5,203.0.113.6",command="echo a b" {OPERATOR_KEY}')
    assert options == 'from="203.0.113.5,203.0.113.6",command="echo a b"'
    assert key == OPERATOR_KEY


@pytest.mark.parametrize(
    "line",
    [
        OPERATOR_KEY + "\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr6d6w3 smuggled",
        "not-a-key AAAA",
        'from="203.0.113.5 ' + OPERATOR_KEY,
    ],
)
def test_malformed_or_multiline_key_lines_are_rejected(line):
    with pytest.raises(InvalidManifest):
        split_key_line(line)


def test_ci_line_replaces_existing_options_with_jump_restriction():
    line = ci_line(f'command="/bin/sh",from="203.0.113.99" {CI_KEY}', ["198.51.100.20", "2001:db8::20"])
    assert line == (
        'from="198.51.100.20,2001:db8::20",no-agent-forwarding,no-X11-forwarding,no-port-forwarding ' + CI_KEY
    )


def test_jump_only_line_opens_only_fleet_ssh_endpoints():
    options, key = split_key_line(jump_only_line(OPERATOR_KEY, ["203.0.113.10:22", "[2001:db8::10]:22"]))
    assert key == OPERATOR_KEY
    assert options.startswith("restrict,port-forwarding,")
    assert 'permitopen="203.0.113.10:22"' in options
    assert 'permitopen="[2001:db8::10]:22"' in options
    assert options.endswith('command="/usr/sbin/nologin"')


def test_jump_only_line_refuses_when_no_endpoints_to_permit():
    with pytest.raises(InvalidManifest):
        jump_only_line(OPERATOR_KEY, [])


def test_bastion_gets_jump_only_lines_for_deploy_and_ci_keys():
    nodes = fleet()
    data = access_data(
        nodes["edge"],
        nodes,
        make_control(),
    )
    assert data["jump_only"] is True
    assert data["ci_cast_user"] is None
    assert data["ci_cast_keys"] == []
    assert {split_key_line(line)[1] for line in data["deploy_keys"]} == {OPERATOR_KEY, CI_KEY}
    assert all(line.endswith(split_key_line(line)[1]) and "nologin" in line for line in data["deploy_keys"])
    assert "[2001:db8::10]:22" in data["fleet_endpoints"]
    assert not any(endpoint.startswith("198.51.100.20") for endpoint in data["fleet_endpoints"])


def test_fleet_node_keeps_deploy_keys_verbatim_and_restricts_ci_keys_to_jump():
    nodes = fleet()
    data = access_data(
        nodes["nlA00"],
        nodes,
        make_control(deploy_keys=[f"no-pty {OPERATOR_KEY}"]),
    )
    assert data["deploy_keys"] == [f"no-pty {OPERATOR_KEY}"]
    assert data["ci_cast_user"] == "astrarium_ci"
    assert data["ci_cast_keys"] == [ci_line(CI_KEY, ["198.51.100.20", "2001:db8::20"])]
    assert data["jump_only"] is False


def test_ci_cast_keys_without_jump_are_invalid():
    nodes = fleet()
    with pytest.raises(InvalidManifest):
        access_data(
            nodes["nlA00"],
            nodes,
            make_control(jump=None),
        )


def test_revoked_ci_cast_keys_do_not_need_jump():
    nodes = fleet()
    control = make_control(jump=None)
    control = control.model_copy(update={"ci": CiControl(cast_user="astrarium_ci", cast_keys=[])})
    data = access_data(
        nodes["nlA00"],
        nodes,
        control,
    )
    assert data["ci_cast_user"] == "astrarium_ci"
    assert data["ci_cast_keys"] == []


@pytest.mark.parametrize(
    ("rebuild", "option"),
    [
        ("hop", 'from="192.0.2.0/24"'),
        ("hop", 'expiry-time="20270101"'),
        ("hop", "verify-required"),
        ("hop", "no-touch-required"),
        ("ci", 'expiry-time="20270101"'),
        ("ci", "verify-required"),
        ("ci", "no-touch-required"),
    ],
)
def test_rebuilt_lines_keep_operator_restrictions(rebuild, option):
    options, key = split_key_line(REBUILDERS[rebuild](f'command="/bin/sh",{option} {CI_KEY}'))
    assert option in split_options(options)
    assert key == CI_KEY


@pytest.mark.parametrize(
    ("node_id", "control"),
    [
        ("nlA00", make_control().model_copy(update={"deploy_user": "core"})),
        ("nlA00", make_control().model_copy(update={"ci": CiControl(cast_user="core", cast_keys=[CI_KEY])})),
        ("edge", make_control().model_copy(update={"deploy_user": "operator"})),
    ],
)
def test_control_account_equal_to_node_login_is_invalid(node_id, control):
    nodes = fleet()
    with pytest.raises(InvalidManifest):
        access_data(
            nodes[node_id],
            nodes,
            control,
        )
