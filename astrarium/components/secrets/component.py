"""CLI: `arium secrets recipients add|remove`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape

from astrarium.components.secrets.controller import ROTATE_REMINDER, RecipientChange, SecretsController
from astrarium.core import BaseComponent, console, err


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


def _report(change: RecipientChange, as_json: bool) -> None:
    if as_json:
        data = {
            "recipients": change.recipients,
            "updated": [str(path) for path in change.updated],
            "rotated": [str(path) for path in change.rotated],
        }
        click.echo(json.dumps(data, indent=2))
        return
    console.print(f"Recipients now: {len(change.recipients)}; files updated: {len(change.updated)}")
    for path in change.updated:
        console.print(f"  {escape(str(path))}")


class SecretsComponent(BaseComponent["AstrariumApp", SecretsController]):
    name = "secrets"
    controller_class = SecretsController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @base.group("secrets")
        def secrets() -> None:
            """Encrypted files under secrets/."""

        @secrets.group("recipients")
        def recipients() -> None:
            """age recipients of .sops.yaml and every encrypted file."""

        @recipients.command("add")
        @click.argument(
            "recipient",
            nargs=-1,
            required=True,
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print JSON.",
        )
        @click.pass_obj
        def add(app: AstrariumApp, recipient: tuple[str, ...], as_json: bool) -> None:
            _report(app.secrets.add_recipients(list(recipient)), as_json)

        @recipients.command("remove")
        @click.argument(
            "recipient",
            nargs=-1,
            required=True,
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print JSON.",
        )
        @click.pass_obj
        def remove(app: AstrariumApp, recipient: tuple[str, ...], as_json: bool) -> None:
            """Remove RECIPIENT, re-wrap and rotate data key of every file."""

            _report(app.secrets.remove_recipients(list(recipient)), as_json)
            err.print(f"[yellow]warning:[/] {escape(ROTATE_REMINDER)}")
