"""`arium fleet provision`: NullForge casts through generated inventory, plus shared cast report output."""

from __future__ import annotations

import asyncio
import json
import sys
from collections.abc import Callable, Mapping, Sequence
from typing import TYPE_CHECKING, cast

import rich_click as click
from rich.markup import escape
from rich.table import Table

from astrarium.components.inventory.controller import CastPreview, CastReport, InventoryController, ProvisionOptions
from astrarium.components.rollout.outcomes import Status, run_exit_code
from astrarium.components.rollout.selection import none_if_blank
from astrarium.core import BaseComponent, command_group, console, err
from astrarium.errors import Declined, ExitCode, PartialFailure, UsageProblem


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp
    from astrarium.components.inventory.paths import CastIdentity
    from astrarium.components.sshcfg.render import Via

STATUS_STYLE: Mapping[Status, str] = {
    Status.OK: "green",
    Status.UNCHANGED: "dim",
    Status.SKIPPED: "yellow",
    Status.FAILED: "red",
    Status.NOT_ATTEMPTED: "red",
}


def echo_masked(line: str) -> None:
    err.print(
        line,
        markup=False,
        highlight=False,
        style="dim",
    )


def reports_json(reports: Mapping[str, CastReport]) -> dict[str, dict[str, object]]:
    return {
        node_id: {
            "status": report.outcome.status.value,
            "reason": report.outcome.reason,
            "changed": list(report.changed),
            "log_tail": list(report.log_tail),
        }
        for node_id, report in sorted(reports.items())
    }


def preview_lines(previews: Sequence[CastPreview]) -> list[str]:
    """Rich lines describing casts before confirmation."""

    lines: list[str] = []
    for preview in previews:
        mode = "dry run" if preview.dry else "cast"
        lines.append(f"[bold]{escape(preview.title)}[/]: {mode} as {preview.identity} via {preview.via}")
        lines += [f"  stage {index}: {escape(label)}" for index, label in enumerate(preview.stages, start=1)]
        lines += [
            f"  batch {index}: {escape(', '.join(batch))}" for index, batch in enumerate(preview.batches, start=1)
        ]
        lines += [
            f"  [yellow]skip[/] {escape(node_id)}: {escape(reason)}"
            for node_id, reason in sorted(preview.skipped.items())
        ]
    return lines


def confirmer(*, yes: bool, dry_run: bool) -> Callable[[list[CastPreview]], bool]:
    """Confirmation callback: preview always on stderr, asks unless --yes or --dry-run (mirrors deploy)."""

    def confirm(previews: list[CastPreview]) -> bool:
        for line in preview_lines(previews):
            err.print(line)
        if yes or dry_run:
            return True
        if not sys.stdin.isatty():
            raise UsageProblem("confirmation needs a terminal", hint="pass --yes")
        return click.confirm(
            "Cast now?",
            default=False,
            err=True,
        )

    return confirm


def render_reports(reports: Mapping[str, CastReport]) -> Table:
    """Outcome table: node, result, reason, number of changed operations."""

    table = Table(
        "Node",
        "Result",
        "Reason",
        "Changes",
    )
    for node_id in sorted(reports):
        report = reports[node_id]
        style = STATUS_STYLE[report.outcome.status]
        reason = report.outcome.reason if report.outcome.reason is not None else ""
        changes = str(len(report.changed)) if report.changed else "-"
        table.add_row(
            escape(node_id),
            f"[{style}]{report.outcome.status.value}[/]",
            escape(reason),
            changes,
        )
    return table


def print_log_tails(reports: Mapping[str, CastReport]) -> None:
    """Masked NullForge log tail of each failed batch, printed once per batch."""

    seen: set[tuple[str, ...]] = set()
    for node_id in sorted(reports):
        tail = tuple(reports[node_id].log_tail)
        if tail and tail not in seen:
            seen.add(tail)
            err.print(f"[red]NullForge log tail ({escape(node_id)} batch):[/]")
            for line in tail:
                err.print(
                    line,
                    markup=False,
                    highlight=False,
                )


def exit_for(reports: Mapping[str, CastReport]) -> None:
    """PartialFailure (exit 3) when any node failed or was not attempted."""

    if run_exit_code({node_id: report.outcome for node_id, report in reports.items()}) != ExitCode.OK:
        raise PartialFailure("some nodes failed or were not attempted")


class InventoryComponent(BaseComponent["AstrariumApp", InventoryController]):
    name = "inventory"
    controller_class = InventoryController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "fleet",
            "Fleet nodes: render, deploy, provision, reach and inspect.",
        ).command("provision")
        @click.option(
            "--limit",
            help="Comma list of node ids, regions and @role; bastions only by id.",
        )
        @click.option(
            "--rune",
            "runes",
            multiple=True,
            help="Cast only this rune (repeatable) instead of the full provision.",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            help="Run cast --dry --diff and report operations that would change.",
        )
        @click.option(
            "--as",
            "identity",
            type=click.Choice(["admin", "ci", "root"]),
            default="admin",
            show_default=True,
            help="Login identity: managed admin user (laptop), CI cast user, or root for first deploy only.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            default=None,
            help="SSH route (default: jump when control.jump is set).",
        )
        @click.option(
            "--canary",
            help="Node cast alone first and checked before the rest.",
        )
        @click.option(
            "--canary-wait",
            type=float,
            default=30.0,
            show_default=True,
            help="Seconds to wait after the canary.",
        )
        @click.option(
            "--stagger",
            type=float,
            default=10.0,
            show_default=True,
            help="Seconds between batches.",
        )
        @click.option(
            "--yes",
            "-y",
            is_flag=True,
            help="Skip the confirmation.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Emit results as JSON.",
        )
        @click.option(
            "--allow-dirty",
            is_flag=True,
            help="Cast although guarded paths have uncommitted changes.",
        )
        @click.option(
            "--follow",
            is_flag=True,
            help="Stream the masked NullForge log.",
        )
        @click.pass_obj
        def provision(
            app: AstrariumApp,
            limit: str | None,
            runes: tuple[str, ...],
            dry_run: bool,
            identity: str,
            via: str | None,
            canary: str | None,
            canary_wait: float,
            stagger: float,
            yes: bool,
            as_json: bool,
            allow_dirty: bool,
            follow: bool,
        ) -> None:
            """Cast NullForge onto nodes: full cast then access and repo runes, or only --rune."""

            options = ProvisionOptions(
                limit=none_if_blank(limit),
                runes=[rune for rune in map(none_if_blank, runes) if rune is not None],
                dry_run=dry_run,
                identity=cast("CastIdentity", identity),
                via=cast("Via | None", via),
                canary=none_if_blank(canary),
                canary_wait=canary_wait,
                stagger=stagger,
                allow_dirty=allow_dirty,
                echo=echo_masked if follow else None,
            )
            reports = asyncio.run(app.inventory.provision(options, confirmer(yes=yes, dry_run=dry_run)))
            if reports is None:
                raise Declined("provision declined", hint="re-run and confirm to cast")
            if as_json:
                click.echo(json.dumps({"nodes": reports_json(reports)}, indent=2))
            else:
                console.print(render_reports(reports))
                print_log_tails(reports)
            exit_for(reports)
