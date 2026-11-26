"""Throwaway namespace, keys and overlay stand-ins: check never holds real secrets."""

from __future__ import annotations

import re
import secrets
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from hexrift.app import HexRiftApp
from hexrift.components.keys.defaults import resolve_node_keys

from astrarium.components.topology.bridge import gen_keys, hexrift_nodes


STANDIN_STRING = "0123456789abcdef0123456789abcdef"
"""Stand-in for encrypted strings: 32 hex chars pass strictest NullForge secret format (telemt users)."""

_ENC_VALUE = re.compile(r"^ENC\[AES256_GCM,data:.*,type:(?P<type>[a-z]+)\]$", re.DOTALL)

_TYPED_STANDINS: dict[str, Any] = {
    "int": 0,
    "float": 0.0,
    "bool": False,
}

_KEY_STANDINS: dict[str, Any] = {
    "role": "none",
}
"""Enum-valued keys: stand-in must stay valid, not STANDIN_STRING."""


def random_namespace() -> str:
    return "n" + secrets.token_hex(16)


def standin_overlay(encrypted: Mapping[str, Any]) -> dict[str, Any]:
    return {key: _standin(value, key) for key, value in encrypted.items() if key != "sops"}


def _standin(value: Any, key: str | None = None) -> Any:
    if isinstance(value, Mapping):
        return {item_key: _standin(item, item_key) for item_key, item in value.items()}
    if isinstance(value, list):
        return [_standin(item, key) for item in value]
    if isinstance(value, str) and (match := _ENC_VALUE.match(value)):
        if key in _KEY_STANDINS:
            return _KEY_STANDINS[key]
        return _TYPED_STANDINS.get(match["type"], STANDIN_STRING)
    return value


def throwaway_keys(head: HexRiftApp, base: HexRiftApp | None, dest: Path) -> tuple[Path, Path]:
    """Key dirs (head, base), nodes whose key config did not change share one key file."""

    head_dir, base_dir = dest / "head", dest / "base"
    head_dir.mkdir(parents=True, exist_ok=True)
    base_dir.mkdir(parents=True, exist_ok=True)
    head_ids = sorted(hexrift_nodes(head))
    gen_keys(
        head,
        head_ids,
        head_dir,
    )
    if base is None:
        return head_dir, base_dir
    base_ids = sorted(hexrift_nodes(base))
    for node_id in base_ids:
        if node_id in head_ids and _key_config(head, node_id) == _key_config(base, node_id):
            shutil.copy2(head_dir / f"{node_id}.yaml", base_dir / f"{node_id}.yaml")
    gen_keys(
        base,
        base_ids,
        base_dir,
    )
    return head_dir, base_dir


def _key_config(app: HexRiftApp, node_id: str) -> object:
    region, node = app.schema.get_node(node_id)
    return resolve_node_keys(
        node,
        region,
        app.schema.config.defaults,
    )
