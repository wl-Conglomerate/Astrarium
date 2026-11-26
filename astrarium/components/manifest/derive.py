"""Effective per-node data: layered, derived and validated with NullForge molds."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from nullforge.molds import FeaturesMold, NetSecMold, SystemMold
from nullforge.smithy.versions import DEFAULT_VERSIONS
from pydantic import ValidationError

from astrarium.components.manifest.firewall import resolve_ssh_port, ssh_rules
from astrarium.components.manifest.layering import merge_with_provenance
from astrarium.components.manifest.loader import validation_lines
from astrarium.components.manifest.models import HEXRIFT_ROLES, Arch, Manifest, NodeSpec, VersionPin
from astrarium.components.manifest.presets import load_preset, role_chain
from astrarium.errors import InvalidManifest


GENERATED_LAYER = "generated"

DERIVED_LAYER = "derived"


@dataclass(frozen=True)
class EffectiveNode:
    """Node after layering, derivation and NullForge validation."""

    id: str
    role: str
    root_role: str
    is_hexrift: bool
    region: str
    fqdn: str | None
    system_hostname: str
    ipv4: str
    ipv6: str | None
    arch: Arch
    ssh_port: int
    ssh_user: str | None
    admin_user: str | None
    host_keys: dict[str, str]
    features: dict[str, Any]
    system: dict[str, Any]
    versions: dict[str, VersionPin]
    runes: list[str]
    provenance: dict[str, str]


def derive_region(node_id: str, node: NodeSpec, hexrift_region: str | None) -> str:
    """HexRift region for hub/exit, else `region` or id prefix split like HexRift."""

    if hexrift_region is not None:
        return hexrift_region
    if node.region is not None:
        return node.region
    prefix = re.split(r"[^a-z]", node_id)[0]
    if not prefix:
        raise InvalidManifest(f"nodes.{node_id}: id has no lowercase prefix, set region explicitly")
    return prefix


def derive_fqdn(manifest: Manifest, node_id: str, node: NodeSpec, root: str) -> str | None:
    """`fqdn` override, else `<id>.<names[root]>.<domain>`, else `<id>.<domain>`, None without domain."""

    if node.fqdn is not None:
        return node.fqdn
    domain = manifest.deployment.domain
    if domain is None:
        return None
    label = manifest.deployment.names.get(root)
    return f"{node_id}.{label}.{domain}" if label else f"{node_id}.{domain}"


def derive_hostname(manifest: Manifest, node_id: str, node: NodeSpec, root: str) -> str:
    """`hostname` override, else `<id>.<names[root]>`, else `<id>`."""

    if node.hostname is not None:
        return node.hostname
    label = manifest.deployment.names.get(root)
    return f"{node_id}.{label}" if label else node_id


def _versions(manifest: Manifest, node: NodeSpec) -> tuple[dict[str, VersionPin], dict[str, str]]:
    versions: dict[str, VersionPin] = {}
    provenance: dict[str, str] = {}
    for layer, pins in (
        ("nullforge", DEFAULT_VERSIONS),
        ("manifest", manifest.versions),
        ("node", node.overrides.versions),
    ):
        for component, pin in pins.items():
            versions[component] = pin
            provenance[f"versions.{component}"] = layer
    return versions, provenance


def _effective(manifest: Manifest, node_id: str, node: NodeSpec, hexrift_region: str | None) -> EffectiveNode:
    chain = role_chain(manifest, node.role)
    root = chain[0]
    preset = load_preset(root)
    layers: list[tuple[str, Mapping[str, Any]]] = [
        (f"preset:{root}", preset),
        ("manifest", {"system": manifest.system, "features": manifest.features}),
    ]
    for role in chain:
        spec = manifest.roles.get(role)
        if spec is not None:
            layers.append((f"role:{role}", {"system": spec.system, "features": spec.features}))
    layers.append((f"node:{node_id}", {"system": node.overrides.system, "features": node.overrides.features}))
    merged, provenance = merge_with_provenance(layers)
    features = merged.get("features", {})
    system = merged.get("system", {})

    netsec = features.setdefault("netsec", {})
    generated = ssh_rules(
        manifest,
        node,
        root,
    )
    if isinstance(netsec, dict):
        rules = netsec.get("firewall_rules", NetSecMold().model_dump(mode="json")["firewall_rules"])
        if isinstance(rules, list):
            netsec["firewall_rules"] = [*resolve_ssh_port(rules, node.ssh.port), *generated]
    if generated:
        base = provenance.get("features.netsec.firewall_rules", "default")
        provenance["features.netsec.firewall_rules"] = f"{base}+{GENERATED_LAYER}"

    hostname = derive_hostname(
        manifest,
        node_id,
        node,
        root,
    )
    system["hostname"] = hostname if "." in hostname else None
    provenance["system.hostname"] = DERIVED_LAYER

    problems: list[str] = []
    try:
        feature_dump = FeaturesMold.model_validate(features).model_dump(mode="json")
    except ValidationError as e:
        problems += validation_lines(e, "features")
    try:
        system_dump = SystemMold.model_validate(system).model_dump(mode="json")
    except ValidationError as e:
        problems += validation_lines(e, "system")
    if problems:
        raise InvalidManifest(f"node {node_id}: " + "; ".join(problems))

    versions, version_provenance = _versions(manifest, node)
    users = feature_dump["users"]
    runes: list[str] = []
    for role in chain:
        spec = manifest.roles.get(role)
        runes += [rune for rune in (spec.runes if spec is not None else []) if rune not in runes]
    return EffectiveNode(
        id=node_id,
        role=node.role,
        root_role=root,
        is_hexrift=root in HEXRIFT_ROLES,
        region=derive_region(
            node_id,
            node,
            hexrift_region if root in HEXRIFT_ROLES else None,
        ),
        fqdn=derive_fqdn(
            manifest,
            node_id,
            node,
            root,
        ),
        system_hostname=hostname,
        ipv4=str(node.ipv4),
        ipv6=str(node.ipv6) if node.ipv6 is not None else None,
        arch=node.arch,
        ssh_port=node.ssh.port,
        ssh_user=node.ssh.user,
        admin_user=next((u["name"] for u in users.get("users", []) if u.get("role") == "admin"), None),
        host_keys={kind: blob for kind, blob in node.host_keys.items()},
        features=feature_dump,
        system=system_dump,
        versions=versions,
        runes=runes,
        provenance={**provenance, **version_provenance},
    )


def _hostname_layers(manifest: Manifest) -> list[str]:
    places: list[tuple[str, Mapping[str, Any]]] = [("system", manifest.system)]
    places += [(f"roles.{name}.system", spec.system) for name, spec in manifest.roles.items()]
    places += [(f"nodes.{node_id}.overrides.system", node.overrides.system) for node_id, node in manifest.nodes.items()]
    return [f"{where}.hostname" for where, system in places if "hostname" in system]


def effective_nodes(manifest: Manifest, hexrift_regions: Mapping[str, str]) -> dict[str, EffectiveNode]:
    """Every manifest node, InvalidManifest lists each failing node and field but never values.

    `system.hostname` at any layer is InvalidManifest: it is derived from `nodes.<id>.hostname`.
    """

    misplaced = _hostname_layers(manifest)
    if misplaced:
        raise InvalidManifest(
            f"{', '.join(misplaced)}: system hostname is derived per node", hint="use nodes.<id>.hostname"
        )
    nodes: dict[str, EffectiveNode] = {}
    problems: list[str] = []
    for node_id, node in manifest.nodes.items():
        try:
            nodes[node_id] = _effective(
                manifest,
                node_id,
                node,
                hexrift_regions.get(node_id),
            )
        except InvalidManifest as e:
            problems.append(e.message)
    if problems:
        raise InvalidManifest("\n".join(problems), hint="see `arium config show --node <id>` for layer sources")
    return nodes
