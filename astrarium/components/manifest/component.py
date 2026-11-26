"""CLI: `arium config show`, `arium config schema`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape
from rich.table import Table

from astrarium.components.manifest.controller import ManifestController
from astrarium.core import BaseComponent, console


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class ManifestComponent(BaseComponent["AstrariumApp", ManifestController]):
    name = "manifest"
    controller_class = ManifestController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @base.group("config")
        def config() -> None:
            """Effective manifest data and its JSON schema."""

        @config.command("show")
        @click.option(
            "--node",
            "node_ids",
            multiple=True,
            help="Node id (repeatable; default: every node).",
        )
        @click.option(
            "--defaults",
            is_flag=True,
            help="Include NullForge defaults no layer sets.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print JSON.",
        )
        @click.pass_obj
        def show(app: AstrariumApp, node_ids: tuple[str, ...], defaults: bool, as_json: bool) -> None:
            """Effective per-node data, secrets masked, with layer each value came from."""

            views = app.manifest.show(list(node_ids), defaults=defaults)
            if as_json:
                click.echo(
                    json.dumps(
                        views,
                        indent=2,
                        sort_keys=True,
                    )
                )
                return
            for node_id, view in views.items():
                title = (
                    f"{node_id} ({view['role']}, region {view['region']}, managed by {'+'.join(view['managed_by'])})"
                )
                table = Table(
                    "Path",
                    "Value",
                    "Layer",
                    title=escape(title),
                    title_justify="left",
                )
                table.add_row(
                    "fqdn",
                    escape(str(view["fqdn"])),
                    "derived",
                )
                table.add_row(
                    "system_hostname",
                    escape(view["system_hostname"]),
                    "derived",
                )
                for row in view["values"]:
                    table.add_row(
                        escape(row["path"]),
                        escape(json.dumps(row["value"])),
                        escape(row["layer"]),
                    )
                console.print(table)

        @config.command("schema")
        @click.option(
            "--out",
            type=click.Path(dir_okay=False, path_type=Path),
            help="Write schema to file instead of stdout.",
        )
        @click.pass_obj
        def schema(app: AstrariumApp, out: Path | None) -> None:
            """JSON schema of astrarium.yaml."""

            text = app.manifest.schema_text()
            if out is None:
                click.echo(text, nl=False)
            else:
                out.write_text(text, encoding="utf-8")
