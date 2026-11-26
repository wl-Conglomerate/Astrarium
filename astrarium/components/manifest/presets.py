"""Built-in role presets and role chains."""

from __future__ import annotations

from importlib.resources import files
from typing import Any

import yaml

from astrarium.components.manifest.models import BUILTIN_ROLES, Manifest
from astrarium.errors import InvalidManifest


def root_role(manifest: Manifest, role: str) -> str:
    return role_chain(manifest, role)[0]


def load_preset(role: str) -> dict[str, Any]:
    """Built-in preset `astrarium/presets/<role>.yaml` as plain dict with `system` and `features` keys."""

    if role not in BUILTIN_ROLES:
        raise InvalidManifest(
            f"no built-in preset for role {role!r}", hint=f"built-in roles: {', '.join(BUILTIN_ROLES)}"
        )
    data = yaml.safe_load((files("astrarium") / "presets" / f"{role}.yaml").read_text(encoding="utf-8"))
    return {"system": data.get("system", {}), "features": data.get("features", {})}


def role_chain(manifest: Manifest, role: str) -> list[str]:
    """Role and its `extends` ancestors, root (built-in) first."""

    chain: list[str] = []
    current: str | None = role
    while current is not None:
        if current in chain:
            cycle = [*chain[chain.index(current) :], current]
            raise InvalidManifest(f"roles: extends cycle {' -> '.join(cycle)}")
        spec = manifest.roles.get(current)
        if spec is None and current not in BUILTIN_ROLES:
            raise InvalidManifest(f"unknown role {current!r}")
        if current in BUILTIN_ROLES and spec is not None and spec.extends is not None:
            raise InvalidManifest(f"roles.{current}: built-in role cannot extend {spec.extends!r}")
        chain.append(current)
        current = spec.extends if spec is not None else None
    return list(reversed(chain))
