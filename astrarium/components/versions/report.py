"""Tables and JSON for `arium versions` output."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from rich.markup import escape
from rich.table import Table

from astrarium.components.versions.controller import ComponentRow, ListReport, OutdatedReport
from astrarium.components.versions.probe import MISMATCH_STATES, NO_HOST_KEYS, VersionCell


STATE_STYLE: Mapping[str, str] = {
    "match": "green",
    "mismatch": "bold red",
    "missing": "bold red",
    "unreachable": "bold red",
    "unknown": "yellow",
    "not probed": "dim",
    NO_HOST_KEYS: "yellow",
}


def list_json(report: ListReport) -> dict[str, Any]:
    return {
        "node": report.node,
        "probed": report.probed,
        "warnings": list(report.warnings),
        "components": [
            {
                "name": row.name,
                "owner": row.owner,
                "pin": row.pin,
                "layer": row.layer,
                "overrides": dict(row.overrides),
                "latest": row.latest.version,
                "head": row.latest.head,
                "apply": row.apply,
                "nodes": {
                    node_id: {
                        "pin": cell.pin,
                        "layer": cell.layer,
                        "installed": cell.installed,
                        "state": cell.state,
                    }
                    for node_id, cell in sorted(row.cells.items())
                },
            }
            for row in report.rows
        ],
    }


def outdated_json(report: OutdatedReport) -> dict[str, Any]:
    return {
        "pre": report.pre,
        "outdated": [
            {
                "component": row.component,
                "where": row.where,
                "pin": row.pin,
                "latest": row.latest,
            }
            for row in report.rows
        ],
        "warnings": list(report.warnings),
    }


def cell_text(cell: VersionCell) -> str:
    """Installed version as shown per node, with pin when they differ."""

    if cell.state == "not probed":
        return "-"
    if cell.state == NO_HOST_KEYS:
        return NO_HOST_KEYS
    if cell.state == "unreachable":
        return "?"
    if cell.state in ("mismatch", "missing"):
        return f"{cell.installed} (pin {cell.pin if cell.pin is not None else '-'})"
    return cell.installed


def installed_summary(cells: Mapping[str, VersionCell]) -> str:
    """`<matching>/<probed> match`, nodes that differ, nodes without host keys (`-` when none apply)."""

    probed = {node_id: cell for node_id, cell in cells.items() if cell.state not in ("not probed", NO_HOST_KEYS)}
    keyless = sorted(node_id for node_id, cell in cells.items() if cell.state == NO_HOST_KEYS)
    parts: list[str] = []
    if probed:
        matching = sum(1 for cell in probed.values() if cell.state == "match")
        parts.append(f"{matching}/{len(probed)} match")
        differing = sorted(node_id for node_id, cell in probed.items() if cell.state in MISMATCH_STATES)
        if differing:
            parts.append(f"differs: {', '.join(differing)}")
    if keyless:
        parts.append(f"{NO_HOST_KEYS}: {', '.join(keyless)}")
    return ", ".join(parts) if parts else "-"


def _latest_text(row: ComponentRow) -> str:
    release = row.latest.version if row.latest.version is not None else "?"
    if row.latest.head is not None:
        return f"{release} (main@{row.latest.head[:12]})"
    return release


def list_table(report: ListReport) -> Table:
    """Fleet view: one row per component."""

    table = Table(
        "Component",
        "Owner",
        "Pin",
        "Layer",
        "Node pins",
        "Installed",
        "Latest",
        "Apply",
        title="Versions",
    )
    for row in report.rows:
        overrides = ", ".join(f"{node_id}={pin}" for node_id, pin in row.overrides.items())
        summary = installed_summary(row.cells)
        if any(cell.state in MISMATCH_STATES for cell in row.cells.values()):
            style = "bold red"
        elif any(cell.state == NO_HOST_KEYS for cell in row.cells.values()):
            style = "yellow"
        else:
            style = "green" if summary != "-" else "dim"
        table.add_row(
            escape(row.name),
            row.owner,
            escape(row.pin if row.pin is not None else "-"),
            escape(row.layer),
            escape(overrides if overrides else "-"),
            f"[{style}]{escape(summary)}[/]",
            escape(_latest_text(row)),
            escape(row.apply),
        )
    return table


def node_table(report: ListReport) -> Table:
    """One node: effective pin, layer, installed version and state per enabled component."""

    node = report.node
    if node is None:
        return list_table(report)
    table = Table(
        "Component",
        "Pin",
        "Layer",
        "Installed",
        "State",
        "Latest",
        "Apply",
        title=f"Versions on {node}",
    )
    for row in report.rows:
        cell = row.cells.get(node)
        if cell is None:
            continue
        style = STATE_STYLE[cell.state]
        table.add_row(
            escape(row.name),
            escape(cell.pin if cell.pin is not None else "-"),
            escape(cell.layer),
            escape(cell_text(cell)),
            f"[{style}]{cell.state}[/]",
            escape(_latest_text(row)),
            escape(row.apply),
        )
    return table


def outdated_table(report: OutdatedReport) -> Table:
    """Pins behind upstream."""

    title = "Outdated pins (prereleases included)" if report.pre else "Outdated pins"
    table = Table(
        "Component",
        "Where",
        "Pin",
        "Latest",
        title=title,
    )
    for row in report.rows:
        table.add_row(
            escape(row.component),
            escape(row.where),
            escape(row.pin),
            f"[green]{escape(row.latest)}[/]",
        )
    return table


def status_entries(cells: Sequence[VersionCell]) -> tuple[dict[str, str], list[str]]:
    """Status columns of one node: component -> shown version, and components in mismatch state."""

    shown = {cell.component: cell_text(cell) for cell in cells}
    mismatched = [cell.component for cell in cells if cell.state in MISMATCH_STATES]
    return shown, mismatched
