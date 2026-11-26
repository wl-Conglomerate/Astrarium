"""Deploy-role sudo commands and CI account privileges derived from features."""

import pytest

from astrarium.runes._policy import ci_access_action, ci_sudoers_body, hop_sshd_dropin, sudo_commands


pytestmark = pytest.mark.unit


def test_sudo_commands_are_base_plus_installed_features():
    installed = {
        "xray": True,
        "haproxy": False,
        "warp": True,
    }
    assert sudo_commands(installed) == [
        "/usr/bin/mv",
        "/bin/systemctl restart xray",
        "/bin/systemctl status xray",
        "/bin/systemctl is-active xray",
        "/bin/systemctl restart cloudflare-warp",
    ]


def test_sudo_commands_without_features_is_only_mv():
    assert sudo_commands({}) == ["/usr/bin/mv"]


def test_ci_cast_user_gets_root_through_nopasswd_all():
    assert ci_sudoers_body("astrarium_ci") == "astrarium_ci ALL=(ALL) NOPASSWD:ALL\n"


def test_ci_access_action_installs_with_keys_revokes_when_emptied_noops_without_cast_user():
    assert ci_access_action("astrarium_ci", ["ssh-ed25519 AAAA sample"]) == "install"
    assert ci_access_action("astrarium_ci", []) == "revoke"
    assert ci_access_action(None, []) == "noop"


def test_hop_sshd_dropin_limits_listed_users_to_local_forwarding():
    lines = [line.strip() for line in hop_sshd_dropin(["github_actions", "astrarium_ci"]).splitlines()]
    match = next(index for index, line in enumerate(lines) if line.startswith("Match User "))
    assert set(lines[match].removeprefix("Match User ").split(",")) == {"github_actions", "astrarium_ci"}
    assert "AllowTcpForwarding local" in lines[match + 1 :]
