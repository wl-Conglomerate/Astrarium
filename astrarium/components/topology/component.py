"""CLI: `arium fleet build --out`, `arium hexrift` passthrough."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape
from rich.table import Table

from astrarium.components.topology.controller import TopologyController
from astrarium.core import BaseComponent, command_group, console, err


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class TopologyComponent(BaseComponent["AstrariumApp", TopologyController]):
    name = "topology"
    controller_class = TopologyController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "fleet",
            "Fleet nodes: render, deploy, provision, reach and inspect.",
        ).command("build")
        @click.option(
            "--limit",
            help="Comma list of node ids, regions and @role.",
        )
        @click.option(
            "--out",
            "out",
            type=click.Path(file_okay=False, path_type=Path),
            required=True,
            help="Empty or new directory outside the repo; receives <id>/config.json and haproxy.cfg (0700).",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print result as JSON.",
        )
        @click.pass_obj
        def build(app: AstrariumApp, limit: str | None, out: Path, as_json: bool) -> None:
            """Render hub/exit configs into --out (files hold private keys)."""

            built, skipped = app.topology.build_out(limit, out)
            if as_json:
                data = {
                    "out": str(out),
                    "nodes": {
                        nid: {
                            "config": str(b.config_json),
                            "haproxy": str(b.haproxy_cfg),
                            "haproxy_wanted": b.haproxy_wanted,
                        }
                        for nid, b in built.items()
                    },
                    "skipped": skipped,
                }
                click.echo(
                    json.dumps(
                        data,
                        indent=2,
                        sort_keys=True,
                    )
                )
                return
            table = Table(
                "Node",
                "HAProxy wanted",
                "Files",
            )
            for node_id, node in sorted(built.items()):
                table.add_row(
                    escape(node_id),
                    "yes" if node.haproxy_wanted else "no",
                    escape(str(node.config_json.parent)),
                )
            console.print(table)
            for node_id, reason in sorted(skipped.items()):
                console.print(f"[yellow]skipped[/] {escape(node_id)}: {escape(reason)}")
            err.print("[yellow]warning:[/] rendered configs contain private keys; delete them when done.")

        @base.command(
            "hexrift",
            context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
            add_help_option=False,
        )
        @click.argument(
            "args",
            nargs=-1,
            type=click.UNPROCESSED,
        )
        @click.pass_obj
        def hexrift(app: AstrariumApp, args: tuple[str, ...]) -> None:
            """Run HexRift read commands (share, derive, show, validate) with real namespace and keys."""

            code = app.topology.hexrift(list(args))
            if code != 0:
                raise SystemExit(code)
