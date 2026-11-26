"""SSH firewall rules generated from `control`."""

from __future__ import annotations

import ipaddress
from typing import Any

from astrarium.components.manifest.models import Manifest, NodeSpec, SshAllow
from astrarium.errors import InvalidManifest


SSH_PORT_KEYWORD = "ssh"
"""`port: ssh` in any firewall rule resolves to node ssh.port (bastion preset uses it)."""


def _network(source: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(source, strict=True)


def resolve_ssh_port(rules: list[Any], port: int) -> list[Any]:
    return [
        {**rule, "port": port} if isinstance(rule, dict) and rule.get("port") == SSH_PORT_KEYWORD else rule
        for rule in rules
    ]


def ssh_sources(manifest: Manifest) -> list[SshAllow]:
    """Validated `control.ssh_allow` entries plus jump node addresses not already listed, text verbatim."""

    sources: list[SshAllow] = []
    problems: list[str] = []
    for entry in manifest.control.ssh_allow:
        allow = entry if isinstance(entry, SshAllow) else SshAllow(source=entry)
        try:
            _network(allow.source)
        except ValueError as e:
            problems.append(f"{allow.source!r}: {e}")
            continue
        sources.append(allow)
    if problems:
        raise InvalidManifest(
            f"control.ssh_allow: {'; '.join(problems)}", hint="use addresses or networks without host bits"
        )
    listed = {_network(allow.source) for allow in sources}
    jump_id = manifest.control.jump
    if jump_id is not None and jump_id in manifest.nodes:
        jump = manifest.nodes[jump_id]
        for address in (jump.ipv4, jump.ipv6):
            if address is not None and _network(str(address)) not in listed:
                sources.append(SshAllow(source=str(address), comment=f"{jump_id} jump SSH"))
    return sources


def ssh_rules(manifest: Manifest, node: NodeSpec, root: str) -> list[dict[str, Any]]:
    """NullForge FirewallRule dicts allowing SSH from every source on node's ssh.port, [] for bastion."""

    if root == "bastion":
        return []
    rules: list[dict[str, Any]] = []
    for allow in ssh_sources(manifest):
        rule: dict[str, Any] = {
            "port": node.ssh.port,
            "proto": "tcp",
            "from_ip": allow.source,
        }
        if allow.comment is not None:
            rule["comment"] = allow.comment
        rules.append(rule)
    return rules
