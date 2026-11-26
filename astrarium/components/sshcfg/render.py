"""Per-identity ssh_config and known_hosts in runtime dir."""

from __future__ import annotations

import base64
import binascii
import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import paramiko
from paramiko.hostkeys import InvalidHostKey

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import ControlSection, Identity
from astrarium.errors import InvalidManifest, UsageProblem
from astrarium.runtime import RuntimeDir, write_private_file


Via = Literal["direct", "jump"]

JUMP_CONCURRENCY = 6
"""Max concurrent connections through jump (sshd MaxStartups defaults to 10)."""

KEY_TYPES: Mapping[str, tuple[str, ...]] = {
    "ed25519": ("ssh-ed25519",),
    "ecdsa": (
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    ),
    "rsa": ("ssh-rsa",),
}
"""Manifest host key family -> SSH key types allowed inside its blob."""


def hop_user(jump: EffectiveNode, identity: Identity, control: ControlSection) -> str:
    return (
        login_user(
            jump,
            "admin",
            control,
        )
        if identity == "admin"
        else control.deploy_user
    )


@dataclass(frozen=True)
class SshPaths:
    config: Path
    known_hosts: Path
    identity: Identity
    via: Via
    nodes: frozenset[str]
    """Node ids rendered into config and known_hosts."""


def resolve_via(control: ControlSection, via: Via | None) -> Via:
    """Explicit route, else jump when control.jump is set."""

    if via is None:
        return "jump" if control.jump else "direct"
    if via == "jump" and not control.jump:
        raise UsageProblem("--via jump needs control.jump in astrarium.yaml")
    return via


def ssh_scope(
    nodes: Mapping[str, EffectiveNode],
    wanted: Iterable[str],
    control: ControlSection,
    via: Via,
) -> dict[str, EffectiveNode]:
    """Wanted nodes in manifest order, plus control.jump when via is jump."""

    keep = set(wanted)
    unknown = sorted(keep - nodes.keys())
    if unknown:
        raise ValueError(f"unknown node ids: {', '.join(unknown)}")
    if via == "jump" and control.jump is not None:
        if control.jump not in nodes:
            raise InvalidManifest(f"control.jump {control.jump} is not a node")
        keep.add(control.jump)
    return {node_id: node for node_id, node in nodes.items() if node_id in keep}


def login_user(node: EffectiveNode, identity: Identity, control: ControlSection) -> str:
    """Login of identity on node as target."""

    if identity == "deploy":
        return control.deploy_user
    if identity == "ci":
        if control.ci is None:
            raise InvalidManifest("identity ci needs control.ci in astrarium.yaml")
        return control.ci.cast_user
    user = node.ssh_user or node.admin_user
    if user is None:
        raise InvalidManifest(f"node {node.id} has unmanaged users, set nodes.{node.id}.ssh.user")
    return user


def _key_type(node_id: str, family: str, blob: str) -> str:
    try:
        raw = base64.b64decode(blob, validate=True)
        (length,) = struct.unpack(">I", raw[:4])
        key_type = raw[4 : 4 + length].decode("ascii")
    except (
        binascii.Error,
        struct.error,
        UnicodeDecodeError,
    ) as e:
        raise InvalidManifest(f"nodes.{node_id}.host_keys.{family} is not a base64 SSH public key") from e
    if key_type not in KEY_TYPES.get(family, ()):
        raise InvalidManifest(f"nodes.{node_id}.host_keys.{family} holds a {key_type} key")
    try:
        key = paramiko.PKey.from_type_string(key_type, raw)
    except (paramiko.SSHException, ValueError) as e:
        raise InvalidManifest(f"nodes.{node_id}.host_keys.{family} is not a valid {key_type} key") from e
    if key.asbytes() != raw:
        raise InvalidManifest(f"nodes.{node_id}.host_keys.{family} is not a valid {key_type} key")
    return key_type


def known_host_names(node: EffectiveNode) -> list[str]:
    """Id, addresses and FQDN, lowercased, bracketed with port when port is not 22."""

    names = dict.fromkeys(
        name.lower()
        for name in (
            node.id,
            node.ipv4,
            node.ipv6,
            node.fqdn,
        )
        if name
    )
    if node.ssh_port == 22:
        return list(names)
    return [f"[{name}]:{node.ssh_port}" for name in names]


def render_known_hosts(nodes: Mapping[str, EffectiveNode]) -> str:
    """One line per node and host key, every name of node on each line."""

    lines = []
    for node in nodes.values():
        names = ",".join(known_host_names(node))
        for family, blob in sorted(node.host_keys.items()):
            lines.append(f"{names} {_key_type(node.id, family, blob)} {blob}")
    return "".join(f"{line}\n" for line in lines)


def render_ssh_config(
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    identity: Identity,
    via: Via,
    known_hosts: Path,
) -> str:
    """Host * defaults, then one block per node (Port only when not 22, ProxyJump only via jump)."""

    jump = control.jump if via == "jump" else None
    if jump is not None and jump not in nodes:
        raise InvalidManifest(f"control.jump {jump} is not a node")
    blocks = [
        [
            "Host *",
            "    StrictHostKeyChecking yes",
            f"    UserKnownHostsFile {known_hosts}",
            "    BatchMode yes",
            "    ConnectTimeout 15",
            "    ServerAliveInterval 10",
            "    ServerAliveCountMax 3",
        ]
    ]
    for node_id, node in nodes.items():
        user = (
            hop_user(
                node,
                identity,
                control,
            )
            if node_id == jump
            else login_user(
                node,
                identity,
                control,
            )
        )
        block = [f"Host {node_id}", f"    HostName {node.ipv4}"]
        if node.ssh_port != 22:
            block.append(f"    Port {node.ssh_port}")
        block.append(f"    User {user}")
        if jump is not None and node_id != jump:
            block.append(f"    ProxyJump {jump}")
        blocks.append(block)
    return "\n".join("\n".join(block) + "\n" for block in blocks)


def _check_known_hosts(path: Path, nodes: Mapping[str, EffectiveNode]) -> None:
    try:
        loaded = paramiko.HostKeys(str(path))
    except InvalidHostKey as e:
        raise InvalidManifest("generated known_hosts does not load in paramiko") from e
    for node in nodes.values():
        lookup = node.ipv4 if node.ssh_port == 22 else f"[{node.ipv4}]:{node.ssh_port}"
        found = loaded.lookup(lookup)
        wanted = {
            _key_type(
                node.id,
                family,
                blob,
            )
            for family, blob in node.host_keys.items()
        }
        if found is None or set(found.keys()) != wanted:
            raise InvalidManifest(f"known_hosts entry for {node.id} does not load for {lookup}")


def write_ssh_files(
    runtime: RuntimeDir,
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    identity: Identity,
    via: Via,
) -> SshPaths:
    """Render, validate and write both files (0600) into runtime subdir `ssh-<identity>-<via>`.

    Every node in `nodes` needs host keys, callers pass ssh_scope of nodes they connect to.
    """

    keyless = sorted(node_id for node_id, node in nodes.items() if not node.host_keys)
    if keyless:
        raise InvalidManifest(f"nodes without host_keys: {', '.join(keyless)}")
    directory = runtime.sub(f"ssh-{identity}-{via}")
    known_hosts = directory / "known_hosts"
    config = directory / "ssh_config"
    write_private_file(known_hosts, render_known_hosts(nodes))
    _check_known_hosts(known_hosts, nodes)
    write_private_file(
        config,
        render_ssh_config(
            nodes,
            control,
            identity,
            via,
            known_hosts,
        ),
    )
    return SshPaths(
        config=config,
        known_hosts=known_hosts,
        identity=identity,
        via=via,
        nodes=frozenset(nodes),
    )
