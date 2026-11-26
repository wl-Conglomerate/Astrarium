"""Secrets overlay: allow-listed paths only, merged into raw manifest before layering."""

from __future__ import annotations

import types
import typing
from collections.abc import Iterator, Mapping
from functools import cache
from typing import Any

from nullforge.molds import BaseMold, FeaturesMold

from astrarium.components.manifest.layering import deep_merge, leaf_paths
from astrarium.errors import InvalidManifest


EXTRA_SENSITIVE_FEATURE_PATHS = frozenset({"zerotrust.token"})
"""Secrets NullForge does not list in `_sensitive_fields`."""

FEATURE_LAYER_PREFIXES = (
    "features",
    "roles.*.features",
    "nodes.*.overrides.features",
)
"""Manifest places that carry NullForge features."""

OTHER_SECRET_PATHS = (
    "notify.discord.webhook_url",
    "notify.discord.thread_id",
    "topology.namespace",
)

OVERLAY_METADATA_KEY = "sops"


def _mold_types(annotation: Any) -> Iterator[type[BaseMold]]:
    if isinstance(annotation, type) and issubclass(annotation, BaseMold):
        yield annotation
        return
    origin = typing.get_origin(annotation)
    if origin is typing.Annotated:
        yield from _mold_types(typing.get_args(annotation)[0])
    elif origin in (typing.Union, types.UnionType):
        for member in typing.get_args(annotation):
            yield from _mold_types(member)


def _sensitive_in(mold: type[BaseMold], prefix: str) -> Iterator[str]:
    for name in getattr(
        mold,
        "_sensitive_fields",
        (),
    ):
        yield f"{prefix}{name}"
    for name, info in mold.model_fields.items():
        origin = typing.get_origin(info.annotation)
        if origin is list:
            # lists are leaves in leaf_paths, so sensitive member makes whole list secret path
            members = [nested for arg in typing.get_args(info.annotation) for nested in _mold_types(arg)]
            if any(list(_sensitive_in(member, "")) for member in members):
                yield f"{prefix}{name}"
        else:
            for nested in _mold_types(info.annotation):
                yield from _sensitive_in(nested, f"{prefix}{name}.")


@cache
def sensitive_feature_paths() -> frozenset[str]:
    return frozenset(_sensitive_in(FeaturesMold, "")) | EXTRA_SENSITIVE_FEATURE_PATHS


def allowed_overlay_paths() -> tuple[str, ...]:
    """Overlay path patterns (`*` matches one key) that may hold values."""

    feature_paths = sorted(sensitive_feature_paths())
    return tuple(f"{prefix}.{path}" for prefix in FEATURE_LAYER_PREFIXES for path in feature_paths) + OTHER_SECRET_PATHS


def _covered(path: str, pattern: str) -> bool:
    parts, wanted = path.split("."), pattern.split(".")
    if len(parts) < len(wanted):
        return False
    return all(
        want in ("*", part)
        for want, part in zip(
            wanted,
            parts,
            strict=False,
        )
    )


def validate_overlay(overlay: Mapping[str, Any]) -> None:
    """InvalidManifest naming every overlay path outside allow-list."""

    patterns = allowed_overlay_paths()
    data = {key: value for key, value in overlay.items() if key != OVERLAY_METADATA_KEY}
    leaves = [path for path, value in leaf_paths(data) if value != {}]
    bad = sorted(path for path in leaves if not any(_covered(path, pattern) for pattern in patterns))
    if bad:
        raise InvalidManifest(
            f"secrets overlay sets paths that must stay in plaintext astrarium.yaml: {', '.join(bad)}",
            hint="overlay holds only secrets: NullForge sensitive fields, Discord webhook, topology.namespace",
        )


def _prune_empty_mappings(data: Mapping[str, Any]) -> dict[str, Any]:
    """Drop empty-mapping leaves (recursively), cascading up while parents become empty."""

    pruned: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, Mapping):
            if not value:
                continue
            nested = _prune_empty_mappings(value)
            if nested:
                pruned[key] = nested
        else:
            pruned[key] = value
    return pruned


def merge_overlay(raw: Mapping[str, Any], overlay: Mapping[str, Any]) -> dict[str, Any]:
    """Raw manifest with overlay deep-merged path by path, `topology` and sops metadata dropped."""

    data = {key: value for key, value in overlay.items() if key not in ("topology", OVERLAY_METADATA_KEY)}
    return deep_merge(raw, _prune_empty_mappings(data))


def overlay_namespace(overlay: Mapping[str, Any]) -> str | None:
    """Real HexRift namespace from overlay `topology.namespace`."""

    topology = overlay.get("topology", {})
    namespace = topology.get("namespace") if isinstance(topology, Mapping) else None
    return namespace if isinstance(namespace, str) and namespace else None
