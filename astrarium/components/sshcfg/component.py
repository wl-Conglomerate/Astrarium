"""`arium fleet ssh NODE [CMD]`."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import rich_click as click

from astrarium.components.manifest.models import Identity
from astrarium.components.sshcfg.controller import SshController
from astrarium.components.sshcfg.render import Via
from astrarium.core import BaseComponent, command_group


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class SshComponent(BaseComponent["AstrariumApp", SshController]):
    """`arium fleet ssh`."""

    name = "sshcfg"
    controller_class = SshController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "fleet",
            "Fleet nodes: render, deploy, provision, reach and inspect.",
        ).command("ssh", context_settings={"allow_interspersed_args": False})
        @click.option(
            "--as",
            "identity",
            type=click.Choice(
                [
                    "deploy",
                    "admin",
                    "ci",
                ]
            ),
            default="deploy",
            show_default=True,
            help="Login identity: deploy user, managed admin user or CI cast user.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            help="SSH path (default: jump when control.jump is set).",
        )
        @click.argument("node")
        @click.argument(
            "command",
            nargs=-1,
            type=click.UNPROCESSED,
        )
        @click.pass_obj
        def ssh(app: AstrariumApp, identity: str, via: str | None, node: str, command: tuple[str, ...]) -> None:
            """Open ssh to NODE (or run COMMAND) with generated config, options go before NODE."""

            code = app.sshcfg.session(
                node,
                list(command),
                identity=cast(Identity, identity),
                via=cast("Via | None", via),
            )
            raise SystemExit(code)
