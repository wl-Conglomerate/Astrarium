"""Plain-dict layering: dicts merge, everything else replaces."""

from __future__ import annotations

import copy
from collections.abc import Iterator, Mapping, Sequence
from typing import Any


def deep_merge(base: Mapping[str, Any], *layers: Mapping[str, Any]) -> dict[str, Any]:
    """New dict: `layers` merged onto `base` in order, dicts recurse, lists and scalars replace, inputs untouched."""

    merged: dict[str, Any] = copy.deepcopy(dict(base))
    for layer in layers:
        _merge_into(merged, layer)
    return merged


def _merge_into(target: dict[str, Any], layer: Mapping[str, Any]) -> None:
    for key, value in layer.items():
        if isinstance(value, Mapping) and isinstance(target.get(key), dict):
            _merge_into(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


def leaf_paths(data: Mapping[str, Any], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """(dotted path, value) of every leaf, lists and empty dicts count as leaves."""

    for key, value in data.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, Mapping) and value:
            yield from leaf_paths(value, path)
        else:
            yield path, value


def merge_with_provenance(layers: Sequence[tuple[str, Mapping[str, Any]]]) -> tuple[dict[str, Any], dict[str, str]]:
    """Merged dict plus dotted leaf path -> name of last layer that set it."""

    merged: dict[str, Any] = {}
    provenance: dict[str, str] = {}
    for name, layer in layers:
        previous = merged
        merged = deep_merge(merged, layer)
        for path, value in leaf_paths(layer):
            if value == {}:
                try:
                    previous_value = get_path(previous, path)
                except KeyError:
                    continue
                if not isinstance(previous_value, Mapping):
                    stale = [known for known in provenance if known == path or known.startswith(f"{path}.")]
                    for known in stale:
                        del provenance[known]
                continue
            stale = [known for known in provenance if known.startswith(f"{path}.") or path.startswith(f"{known}.")]
            for known in stale:
                del provenance[known]
            provenance[path] = name
    return merged, provenance


def get_path(data: Mapping[str, Any], path: str) -> Any:
    """Value at dotted path, KeyError when absent."""

    node: Any = data
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            raise KeyError(path)
        node = node[part]
    return node


def set_path(data: dict[str, Any], path: str, value: Any) -> None:
    """Set value at dotted path, creating intermediate dicts."""

    *parents, last = path.split(".")
    node = data
    for part in parents:
        node = node.setdefault(part, {})
    node[last] = value
