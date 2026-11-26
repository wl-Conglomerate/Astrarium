"""CLI: `arium keys gen`, `arium keys show`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import rich_click as click
import yaml
from rich.markup import escape

from astrarium.components.keys.controller import KeysController
from astrarium.core import BaseComponent, console, err


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class KeysComponent(BaseComponent["AstrariumApp", KeysController]):
    name = "keys"
    controller_class = KeysController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @base.group("keys")
        def keys() -> None:
            """HexRift key files under secrets/keys (encrypted)."""

        @keys.command("gen")
        @click.argument(
            "node_ids",
            nargs=-1,
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print created ids as JSON.",
        )
        @click.pass_obj
        def gen(app: AstrariumApp, node_ids: tuple[str, ...], as_json: bool) -> None:
            """Create missing key files (never rotates existing ones), then commit secrets/keys."""

            created = app.keys.gen(list(node_ids))
            if as_json:
                click.echo(json.dumps({"created": created}))
                return
            if not created:
                console.print("Every selected node already has a key file.")
                return
            for node_id in created:
                console.print(f"[green]created[/] secrets/keys/{escape(node_id)}.yaml")
            console.print("Commit secrets/keys/ before deploying.")

        @keys.command("show")
        @click.argument("node_id")
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print JSON.",
        )
        @click.pass_obj
        def show(app: AstrariumApp, node_id: str, as_json: bool) -> None:
            """Print decrypted key file of NODE_ID (private keys: terminal only)."""

            data = app.keys.show(node_id)
            err.print("[yellow]warning:[/] output contains private keys.")
            if as_json:
                click.echo(
                    json.dumps(
                        data,
                        indent=2,
                        sort_keys=True,
                    )
                )
            else:
                click.echo(yaml.safe_dump(data, sort_keys=True), nl=False)
