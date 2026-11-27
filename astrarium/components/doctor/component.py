"""CLI: `arium repo doctor`."""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape
from rich.table import Table

from astrarium.components.doctor.controller import DoctorController
from astrarium.core import BaseComponent, command_group, console
from astrarium.errors import AstrariumError


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


STYLE = {
    "pass": "green",
    "warn": "yellow",
    "fail": "red",
}


class DoctorFailed(AstrariumError):
    """At least one doctor rule failed (exit 1)."""


class DoctorComponent(BaseComponent["AstrariumApp", DoctorController]):
    name = "doctor"
    controller_class = DoctorController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "repo",
            "Deployment repo: create, validate and test it.",
        ).command("doctor")
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print checks as JSON.",
        )
        @click.pass_obj
        def doctor(app: AstrariumApp, as_json: bool) -> None:
            """Check prerequisites, secrets, manifest, topology and their consistency (changes nothing)."""

            found = app.doctor.run()
            if as_json:
                click.echo(json.dumps([asdict(check) for check in found], indent=2))
            else:
                table = Table(
                    "Check",
                    "Result",
                    "Detail",
                    "Fix",
                )
                for check in found:
                    style = STYLE[check.status]
                    table.add_row(
                        escape(check.name),
                        f"[{style}]{check.status}[/]",
                        escape(check.detail),
                        escape(check.hint or ""),
                    )
                console.print(table)
            failed = [check.name for check in found if check.status == "fail"]
            if failed:
                raise DoctorFailed(f"{len(failed)} check(s) failed: {', '.join(failed)}")
