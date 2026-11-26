"""HexRift bridge: temp topology with real namespace, node list, derived identities, key generation, builds."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID

import yaml
from hexrift.app import HexRiftApp
from hexrift.components.derive.identity import Namespace
from hexrift.errors import Error as HexRiftError

from astrarium.errors import ExternalToolError, InvalidManifest


NAMESPACE_PLACEHOLDER = "namespace.placeholder.invalid"

NAMESPACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+$")

_WANTED = re.compile(r"^\s*(frontend|listen)\s+\S", re.IGNORECASE | re.MULTILINE)

_NAMESPACE_LINE = re.compile(
    r"^(\s+namespace:\s*)(['\"]?)" + re.escape(NAMESPACE_PLACEHOLDER) + r"\2(\s*(#.*)?)$", re.MULTILINE
)


def haproxy_wanted(cfg_text: str) -> bool:
    return _WANTED.search(cfg_text) is not None


def _wrap(exc: HexRiftError) -> ExternalToolError:
    return ExternalToolError(f"hexrift: {exc}")


def hexrift_nodes(app: HexRiftApp) -> dict[str, HexRiftNode]:
    return {
        node.id: HexRiftNode(
            id=node.id,
            region=region.id,
            type=region.type.value,
            hostname=node.hostname,
        )
        for region, node in app.schema.get_all_nodes()
    }


@dataclass(frozen=True)
class HexRiftNode:
    id: str
    region: str
    type: Literal["exit", "hub"]
    hostname: str


@dataclass(frozen=True)
class BuiltNode:
    node_id: str
    config_json: Path
    haproxy_cfg: Path
    haproxy_wanted: bool


def topology_namespace(topology: Path) -> str | None:
    """`global.namespace` of topology file, None when absent or malformed."""

    try:
        data = yaml.safe_load(topology.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise InvalidManifest(f"{topology.name}: cannot read YAML ({type(e).__name__})") from e
    if not isinstance(data, dict):
        return None
    section = data.get("global", {})
    value = section.get("namespace") if isinstance(section, dict) else None
    return value if isinstance(value, str) else None


def materialize_topology(src: Path, dest: Path, namespace: str) -> Path:
    """Copy of `src` at `dest` (0600) with placeholder namespace replaced by `namespace`, other bytes unchanged."""

    if not NAMESPACE_PATTERN.fullmatch(namespace):
        raise InvalidManifest("overlay topology.namespace must match HexRift DNS-name charset [A-Za-z0-9_.-]")
    if topology_namespace(src) != NAMESPACE_PLACEHOLDER:
        raise InvalidManifest(
            f"{src.name}: global.namespace must be the placeholder {NAMESPACE_PLACEHOLDER!r}",
            hint="the real namespace lives in the overlay at topology.namespace",
        )
    text, count = _NAMESPACE_LINE.subn(
        lambda match: f"{match.group(1)}{match.group(2)}{namespace}{match.group(2)}{match.group(3)}",
        src.read_text(encoding="utf-8"),
    )
    if count != 1:
        raise InvalidManifest(
            f"{src.name}: write global.namespace as a plain `namespace: {NAMESPACE_PLACEHOLDER}` line"
        )
    fd = os.open(
        dest,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(
        fd,
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(text)
    return dest


def open_hexrift(topology: Path) -> HexRiftApp:
    """HexRift app on `topology` with schema loaded, HexRift errors -> ExternalToolError without markup."""

    app = HexRiftApp(topology)
    try:
        app.schema.load(topology)
    except HexRiftError as e:
        raise _wrap(e) from None
    return app


def _identities(app: HexRiftApp) -> Iterator[str]:
    for user in app.derive.derive_users():
        yield user.uuid
        if user.server_uuid is not None:
            yield user.server_uuid
        for guest in user.guests:
            yield from (guest.uuid, guest.short_id)
    for portal in app.derive.derive_portals():
        yield from (portal.uuid, portal.short_id)
    for group in app.derive.derive_groups():
        yield group.short_id
    for node in app.derive.derive_nodes():
        yield from (value for value in (node.short_id, node.hub_short_id) if value is not None)
        if node.hub_exit_uuids is not None:
            for hub_exit in node.hub_exit_uuids.values():
                yield from (hub_exit, str(Namespace.warp_uuid(UUID(hub_exit))))


def derived_identities(app: HexRiftApp) -> list[str]:
    """Namespace-derived UUIDs and shortIds via HexRift derive: users, servers, guests, portals, groups, hub-exit."""

    try:
        return sorted(set(_identities(app)))
    except HexRiftError as e:
        raise _wrap(e) from None


def gen_keys(app: HexRiftApp, node_ids: Iterable[str], keys_dir: Path) -> list[str]:
    """Generate missing key files in `keys_dir` (never force: hub keys never rotate here), return ids that got one."""

    created: list[str] = []
    for node_id in node_ids:
        try:
            if app.keys.gen_keys(
                node_id,
                keys_dir,
                force=False,
            ):
                created.append(node_id)
        except HexRiftError as e:
            raise _wrap(e) from None
    return created


def build_nodes(app: HexRiftApp, node_ids: list[str], keys_dir: Path, out_dir: Path) -> dict[str, BuiltNode]:
    """Render config.json and haproxy.cfg of each node into `<out_dir>/<id>/`."""

    built: dict[str, BuiltNode] = {}
    for node_id in node_ids:
        try:
            app.render.build(
                node_id,
                out_dir,
                keys_dir,
                xray=True,
                haproxy=True,
            )
        except HexRiftError as e:
            raise ExternalToolError(f"hexrift build {node_id}: {e}") from None
        node_dir = out_dir / node_id
        haproxy_cfg = node_dir / "haproxy.cfg"
        built[node_id] = BuiltNode(
            node_id=node_id,
            config_json=node_dir / "config.json",
            haproxy_cfg=haproxy_cfg,
            haproxy_wanted=haproxy_wanted(haproxy_cfg.read_text(encoding="utf-8")),
        )
    return built
