"""Deploy and CI account privileges derived from node features (pure, shared by runes and tests)."""

from collections.abc import Mapping, Sequence
from typing import Literal


CiAccessAction = Literal["install", "revoke", "noop"]

BASE_SUDO: tuple[str, ...] = ("/usr/bin/mv",)

FEATURE_PRIVILEGES: Mapping[str, tuple[str, ...]] = {
    "xray": (
        "/bin/systemctl restart xray",
        "/bin/systemctl status xray",
        "/bin/systemctl is-active xray",
    ),
    "haproxy": (
        "/bin/systemctl enable --now haproxy",
        "/bin/systemctl disable --now haproxy",
        "/bin/systemctl restart haproxy",
        "/bin/systemctl reload haproxy",
        "/bin/systemctl status haproxy",
        "/bin/systemctl is-active haproxy",
        "/usr/sbin/haproxy",
    ),
    "warp": ("/bin/systemctl restart cloudflare-warp",),
}
"""Feature attr -> sudo commands the deploy-role user gets, same as legacy Deployment automation."""

HOP_SSHD_DROPIN_PATH = "/etc/ssh/sshd_config.d/45-astrarium-hop.conf"
"""sshd drop-in for jump-only hop accounts, read through Include, its Match block ends with file."""


def ci_sudoers_body(user: str) -> str:
    return f"{user} ALL=(ALL) NOPASSWD:ALL\n"


def hop_sshd_dropin(users: Sequence[str]) -> str:
    return (
        "# Managed by astrarium deploy_access rune (jump-only hop accounts)\n"
        f"Match User {','.join(users)}\n"
        "    AllowTcpForwarding local\n"
        "    AllowStreamLocalForwarding no\n"
        "    PermitTTY no\n"
    )


def sudo_commands(installed: Mapping[str, bool]) -> list[str]:
    """Base commands plus commands of installed features."""

    commands = list(BASE_SUDO)
    for feature, feature_commands in FEATURE_PRIVILEGES.items():
        if installed.get(feature, False):
            commands.extend(feature_commands)
    return commands


def ci_access_action(cast_user: str | None, cast_keys: Sequence[str]) -> CiAccessAction:
    """Desired ci_access rune action from host data: no cast user noops, empty keys revoke."""

    if cast_user is None:
        return "noop"
    return "install" if cast_keys else "revoke"
