"""pyinfra inventory module for NullForge casts: one list per root role, host data per node."""

from __future__ import annotations

import keyword
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from astrarium.components.inventory.access import access_data
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import ControlSection, VersionPin
from astrarium.components.sshcfg.render import SshPaths, login_user
from astrarium.errors import AstrariumError, InvalidManifest
from astrarium.runes._policy import FEATURE_PRIVILEGES, sudo_commands
from astrarium.runtime import RuntimeDir, write_private_file


INVENTORY_FILENAME = "astrarium_inventory.py"
"""File stem becomes pyinfra group (pyinfra_cli/inventory.py:323,349-350). Underscore keeps it off NODE_ID_PATTERN."""

ASTRARIUM_COMPONENTS = frozenset({"xray"})
"""Components astrarium manages itself, never pinned into NullForge host data."""


def nullforge_versions(versions: Mapping[str, VersionPin]) -> dict[str, str]:
    return {name: pin for name, pin in versions.items() if isinstance(pin, str) and name not in ASTRARIUM_COMPONENTS}


def _without_root_key_copy(features: dict[str, Any]) -> dict[str, Any]:
    """CI and root casts turn off copy_root_keys on every user: NullForge copies login user's authorized_keys there."""

    users = features.get("users", {})
    entries = [{**entry, "copy_root_keys": False} for entry in users.get("users", [])]
    return {**features, "users": {**users, "users": entries}}


def _with_deploy_user(features: dict[str, Any], control: ControlSection) -> dict[str, Any]:
    """Fleet nodes: inject deploy user as role=deploy features.users entry, NullForge users rune owns it."""

    installed = {attr: bool(features.get(attr, {}).get("install", False)) for attr in FEATURE_PRIVILEGES}
    users = features.get("users", {})
    entries = [
        *users.get("users", []),
        {
            "name": control.deploy_user,
            "role": "deploy",
            "sudo_commands": sudo_commands(installed),
            "ssh_keys": list(control.deploy_keys),
            "shell": "/bin/bash",
            "copy_root_keys": False,
        },
    ]
    return {**features, "users": {**users, "users": entries}}


def _with_user_profiles(features: dict[str, Any]) -> dict[str, Any]:
    """Fill empty profiles.users with admin user names only: deploy stays plain bash, root keeps its own."""

    profiles = features.get("profiles", {})
    entries = features.get("users", {}).get("users", [])
    if profiles.get("users") or not entries:
        return features
    names = sorted({entry["name"] for entry in entries if entry.get("role") == "admin"})
    return {**features, "profiles": {**profiles, "for_root": True, "users": names}}


def host_data(
    node: EffectiveNode,
    fleet: Mapping[str, EffectiveNode],
    ssh: SshPaths,
    control: ControlSection,
) -> dict[str, Any]:
    """pyinfra host data for one node, access data drawn from full fleet, never cast scope."""

    features = node.features
    if node.root_role != "bastion":
        features = _with_deploy_user(features, control)
        features = _with_user_profiles(features)
    if ssh.identity in ("ci", "root"):
        features = _without_root_key_copy(features)
    return {
        "zone": node.root_role,
        "system": node.system,
        "features": features,
        "versions": nullforge_versions(node.versions),
        "astrarium": access_data(
            node,
            fleet,
            control,
        ),
        "ssh_config_file": str(ssh.config),
        "ssh_known_hosts_file": str(ssh.known_hosts),
        "ssh_strict_host_key_checking": "yes",
        "ssh_user": login_user(
            node,
            ssh.identity,
            control,
        ),
    }


def render_inventory(
    targets: Mapping[str, EffectiveNode],
    fleet: Mapping[str, EffectiveNode],
    ssh: SshPaths,
    control: ControlSection,
) -> str:
    """Python module text `<root role> = [(node id, host data), ...]`, covering exactly given targets.

    `fleet` is full manifest fleet, used only for access data (jump lookup, fleet endpoints),
    so it never shrinks with cast scope, `targets` are nodes this cast actually renders.
    """

    missing = sorted(set(targets) - ssh.nodes)
    if missing:
        # no Host block in ssh.config for these ids -> pyinfra would dial them through DNS
        raise InvalidManifest(f"targets not covered by ssh scope: {', '.join(missing)}")
    for path in (ssh.config, ssh.known_hosts):
        if not path.is_absolute() or not path.is_file():
            # pyinfra ignores missing ssh_config_file silently and would dial node id as hostname
            raise AstrariumError(f"SSH file {path} is missing or relative")
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for node_id in sorted(targets):
        node = targets[node_id]
        groups.setdefault(node.root_role, []).append(
            (
                node_id,
                host_data(
                    node,
                    fleet,
                    ssh,
                    control,
                ),
            )
        )
    lines = ['"""Generated by astrarium for one run; holds decrypted secrets."""', ""]
    for group in sorted(groups):
        if not group.isidentifier() or keyword.iskeyword(group):
            raise AstrariumError(f"role {group!r} cannot name a pyinfra group")
        lines.append(f"{group} = {groups[group]!r}")
    return "\n".join(lines) + "\n"


def write_inventory(runtime: RuntimeDir, text: str) -> Path:
    """Write inventory 0600 into own runtime subdir, used as cast cwd (no config.py or group_data/ there)."""

    path = runtime.sub("inventory") / INVENTORY_FILENAME
    write_private_file(path, text)
    return path
