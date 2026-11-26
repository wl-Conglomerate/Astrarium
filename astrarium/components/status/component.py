"""`arium fleet status` (config part, versions columns come from versions registry)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import asdict
from typing import TYPE_CHECKING, cast

import rich_click as click
from rich.table import Table
from rich.text import Text

from astrarium.components.rollout.selection import none_if_blank
from astrarium.components.sshcfg.render import Via
from astrarium.components.status.controller import (
    DIFFERS,
    MATCH,
    NodeStatus,
    StatusController,
    StatusOptions,
    status_exit_code,
)
from astrarium.core import BaseComponent, command_group, console
from astrarium.errors import ExitCode, PartialFailure


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


_CONFIG_STYLES = {MATCH: "green", DIFFERS: "bold red"}


def render_status(statuses: Mapping[str, NodeStatus], *, collapse: bool = False) -> Table:
    """One row per node, or per identical group with `collapse`. Mismatches highlighted."""

    components = sorted({name for status in statuses.values() for name in status.versions})
    table = Table(title="Status")
    for column in (
        "node",
        "role",
        "region",
        "reachable",
        "config",
        *components,
    ):
        table.add_column(column)
    entries = [([status.node_id], status) for status in statuses.values()]
    if collapse:
        by_key: dict[tuple, tuple[list[str], NodeStatus]] = {}
        for status in statuses.values():
            key = (
                status.role,
                status.region,
                status.reachable,
                status.config,
                tuple(status.versions.get(name, "-") for name in components),
                tuple(sorted(status.mismatches)),
            )
            if key in by_key:
                by_key[key][0].append(status.node_id)
            else:
                by_key[key] = ([status.node_id], status)
        entries = list(by_key.values())
    for node_ids, status in entries:
        reach = Text("yes", style="green") if status.reachable else Text("NO", style="bold red")
        config = Text(status.config, style=_CONFIG_STYLES.get(status.config, "yellow"))
        versions = [
            Text(status.versions.get(name, "-"), style="bold red" if name in status.mismatches else "")
            for name in components
        ]
        table.add_row(
            Text(",".join(node_ids)),
            Text(status.role),
            Text(status.region),
            reach,
            config,
            *versions,
        )
    return table


class StatusComponent(BaseComponent["AstrariumApp", StatusController]):
    """`arium fleet status`."""

    name = "status"
    controller_class = StatusController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "fleet",
            "Fleet nodes: render, deploy, provision, reach and inspect.",
        ).command()
        @click.option(
            "--limit",
            help="Comma list of node ids, regions and @role (union).",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            help="SSH path (default: jump when control.jump is set).",
        )
        @click.option(
            "--no-config",
            is_flag=True,
            help="Skip built-vs-live config comparison (no key decryption).",
        )
        @click.option(
            "--all",
            "show_all",
            is_flag=True,
            help="Also list every NullForge default component.",
        )
        @click.option(
            "--collapse",
            is_flag=True,
            help="dshbak -c style: one row per group of nodes with identical status.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print JSON.",
        )
        @click.pass_obj
        def status(
            app: AstrariumApp,
            limit: str | None,
            via: str | None,
            no_config: bool,
            show_all: bool,
            collapse: bool,
            as_json: bool,
        ) -> None:
            """Show reachability and built-vs-live config per node (read-only)."""

            opts = StatusOptions(
                limit=none_if_blank(limit),
                via=cast("Via | None", via),
                no_config=no_config,
                all=show_all,
            )
            statuses = asyncio.run(app.status.collect(opts))
            if as_json:
                click.echo(json.dumps([asdict(status) for status in statuses.values()], indent=2))
            else:
                console.print(render_status(statuses, collapse=collapse))
            if status_exit_code(statuses) is ExitCode.PARTIAL:
                raise PartialFailure("some nodes are unreachable or differ from the manifest")
