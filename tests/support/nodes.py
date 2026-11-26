"""EffectiveNode test builder."""

from __future__ import annotations

import re
from typing import Any

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import Arch, VersionPin
from tests.support.hostkeys import ed25519_blob


HEXRIFT_ROOTS = ("exit", "hub")


def make_node(
    node_id: str,
    *,
    role: str = "exit",
    root_role: str | None = None,
    region: str | None = None,
    ipv4: str = "203.0.113.10",
    ipv6: str | None = None,
    fqdn: str | None = None,
    arch: Arch = "x86_64",
    ssh_port: int = 22,
    ssh_user: str | None = None,
    admin_user: str | None = "operator",
    host_keys: dict[str, str] | None = None,
    features: dict[str, Any] | None = None,
    versions: dict[str, VersionPin] | None = None,
) -> EffectiveNode:
    """EffectiveNode with derived fields filled as derive.py computes them."""

    root = root_role or role
    return EffectiveNode(
        id=node_id,
        role=role,
        root_role=root,
        is_hexrift=root in HEXRIFT_ROOTS,
        region=region or re.split(r"[^a-z]", node_id)[0],
        fqdn=fqdn,
        system_hostname=node_id,
        ipv4=ipv4,
        ipv6=ipv6,
        arch=arch,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        admin_user=admin_user,
        host_keys=host_keys if host_keys is not None else {"ed25519": ed25519_blob()},
        features=features
        if features is not None
        else {"haproxy": {"install": False}, "xray": {"install": root in HEXRIFT_ROOTS}},
        system={},
        versions=versions if versions is not None else {},
        runes=[],
        provenance={},
    )
