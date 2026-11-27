"""`--limit` parsing and node selection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.errors import Refused, UsageProblem


NOT_HEXRIFT = "not a HexRift node"


@dataclass(frozen=True)
class Selection:
    nodes: list[str]
    skipped: dict[str, str]


def none_if_blank(value: str | None) -> str | None:
    """CLI value with surrounding whitespace stripped, None when empty (dispatch input left blank)."""

    text = value.strip() if value is not None else ""
    return text if text else None


def parse_limit(expr: str | None) -> list[str]:
    """Comma list -> entries, whitespace stripped, empty and repeated entries dropped."""

    if expr is None:
        return []
    return list(dict.fromkeys(entry.strip() for entry in expr.split(",") if entry.strip()))


def _matches(entry: str, node: EffectiveNode) -> bool:
    if entry.startswith("@"):
        return entry[1:] in (node.role, node.root_role)
    return entry in (node.id, node.region)


def select(nodes: Mapping[str, EffectiveNode], limit: str | None, *, hexrift_only: bool) -> Selection:
    """Union of node ids, regions and @roles, manifest order, every entry must match some node."""

    entries = parse_limit(limit)
    if limit is not None and not entries:
        raise UsageProblem("--limit has no entries")
    if not entries:
        return Selection(nodes=[nid for nid, node in nodes.items() if node.is_hexrift or not hexrift_only], skipped={})
    unmatched = [entry for entry in entries if not any(_matches(entry, node) for node in nodes.values())]
    if unmatched:
        raise Refused(
            f"--limit entries match no node: {', '.join(unmatched)}",
            hint="entries are node ids, regions or @role",
        )
    matched = [nid for nid, node in nodes.items() if any(_matches(entry, node) for entry in entries)]
    chosen = [nid for nid in matched if nodes[nid].is_hexrift or not hexrift_only]
    skipped = {nid: NOT_HEXRIFT for nid in matched if nid not in chosen}
    return Selection(nodes=chosen, skipped=skipped)
