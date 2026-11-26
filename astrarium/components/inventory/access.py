"""Authorized key lines and `astrarium` host data consumed by deploy_access and ci_access runes."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.keylines import split_key_line, split_options
from astrarium.components.manifest.models import ControlSection
from astrarium.errors import InvalidManifest


CI_OPTIONS = "no-agent-forwarding,no-X11-forwarding,no-port-forwarding"

NOLOGIN = "/usr/sbin/nologin"

KEPT_OPTIONS = frozenset(
    {
        "from",
        "expiry-time",
        "verify-required",
        "no-touch-required",
    }
)
"""Operator restrictions carried from source line into rebuilt hop and CI lines."""


def _kept_options(options: str, names: frozenset[str]) -> list[str]:
    return [option for option in split_options(options) if option.split("=", 1)[0].lower() in names]


def ci_line(line: str, jump_addresses: Iterable[str]) -> str:
    """CI cast key usable only from jump addresses, operator expiry and FIDO options kept.

    Operator from= stays on bastion hop line only: nodes see jump address, and sshd rejects line with two from=.
    """

    options, key = split_key_line(line)
    kept = _kept_options(options, KEPT_OPTIONS - {"from"})
    return (
        ",".join(
            [
                f'from="{",".join(jump_addresses)}"',
                CI_OPTIONS,
                *kept,
            ]
        )
        + f" {key}"
    )


def jump_only_line(line: str, endpoints: Iterable[str]) -> str:
    """Hop-only key, ProxyJump channels to listed endpoints, no shell, operator restrictions kept."""

    resolved = list(endpoints)
    if not resolved:
        raise InvalidManifest("jump-only key has no endpoints to permit (bastion has no other fleet node)")
    options, key = split_key_line(line)
    permits = [f'permitopen="{endpoint}"' for endpoint in resolved]
    kept = _kept_options(options, KEPT_OPTIONS)
    return (
        ",".join(
            [
                "restrict",
                "port-forwarding",
                *permits,
                f'command="{NOLOGIN}"',
                *kept,
            ]
        )
        + f" {key}"
    )


def fleet_endpoints(nodes: Mapping[str, EffectiveNode]) -> list[str]:
    """SSH endpoints of every non-bastion node, `ip:port` and `[ipv6]:port`."""

    endpoints: list[str] = []
    for node_id in sorted(nodes):
        node = nodes[node_id]
        if node.root_role == "bastion":
            continue
        endpoints.append(f"{node.ipv4}:{node.ssh_port}")
        if node.ipv6:
            endpoints.append(f"[{node.ipv6}]:{node.ssh_port}")
    return endpoints


def check_accounts(node: EffectiveNode, control: ControlSection) -> None:
    """InvalidManifest when deploy or CI cast account is also node's own login or managed admin user."""

    accounts = {control.deploy_user, *([control.ci.cast_user] if control.ci is not None else [])}
    entries = node.features.get("users", {}).get("users", [])
    admins = {entry["name"] for entry in entries if entry.get("role") == "admin"}
    logins = {user for user in (node.ssh_user, *admins) if user is not None}
    clashes = sorted(accounts & logins)
    if clashes:
        raise InvalidManifest(
            f"node {node.id}: {', '.join(clashes)} is both a control account and the node's own login",
            hint="control.deploy_user and control.ci.cast_user must differ from ssh.user and admin users (role=admin)",
        )


def access_data(node: EffectiveNode, nodes: Mapping[str, EffectiveNode], control: ControlSection) -> dict[str, Any]:
    """Host data key `astrarium` for one node, final key lines per account."""

    check_accounts(node, control)
    ci_keys = list(control.ci.cast_keys) if control.ci is not None else []
    for line in [*control.deploy_keys, *ci_keys]:
        split_key_line(line)

    if node.root_role == "bastion":
        endpoints = fleet_endpoints(nodes)
        hop_lines = [jump_only_line(line, endpoints) for line in [*control.deploy_keys, *ci_keys]]
        return {
            "deploy_user": control.deploy_user,
            "deploy_keys": list(dict.fromkeys(hop_lines)),
            "ci_cast_user": None,
            "ci_cast_keys": [],
            "jump_only": True,
            "fleet_endpoints": endpoints,
        }

    ci_lines: list[str] = []
    if ci_keys:
        jump = nodes.get(control.jump) if control.jump is not None else None
        if jump is None:
            raise InvalidManifest(
                "control.ci.cast_keys need control.jump",
                hint="CI cast keys are restricted to the jump host addresses",
            )
        addresses = [jump.ipv4, *([jump.ipv6] if jump.ipv6 else [])]
        ci_lines = list(dict.fromkeys(ci_line(line, addresses) for line in ci_keys))
    return {
        "deploy_user": control.deploy_user,
        "deploy_keys": list(control.deploy_keys),
        "ci_cast_user": control.ci.cast_user if control.ci is not None else None,
        "ci_cast_keys": ci_lines,
        "jump_only": False,
        "fleet_endpoints": [],
    }
