"""`arium fleet deploy` command."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import TYPE_CHECKING, Any, cast

import rich_click as click
from rich.console import Console
from rich.table import Table
from rich.text import Text

from astrarium.components.rollout.artifacts import parse_artifact_options
from astrarium.components.rollout.controller import DeployOptions, DeployPlan, DeployReport, RolloutController
from astrarium.components.rollout.outcomes import PREREQUISITE, Status, run_exit_code
from astrarium.components.rollout.report import outcomes_json, render_table
from astrarium.components.rollout.selection import none_if_blank
from astrarium.components.sshcfg.render import Via
from astrarium.core import BaseComponent, command_group, console, err
from astrarium.errors import Declined, ExitCode, PartialFailure, Refused, UsageProblem


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


def show_plan(plan: DeployPlan, out: Console = console) -> None:
    """Plan table, notes and masked diffs (stdout unless `out` given)."""

    table = Table(title=f"Plan {plan.run_id} (commit {plan.commit[:12]}, via {plan.via})")
    for column in (
        "node",
        "config.json",
        "haproxy.cfg",
        "xray",
    ):
        table.add_column(column)
    for node_id, node_plan in plan.plans.items():
        table.add_row(
            Text(node_id),
            "change" if node_plan.config else "-",
            "change" if node_plan.haproxy else "-",
            Text(node_plan.binary.label if node_plan.binary else "-"),
        )
    for node_id, outcome in plan.settled.items():
        table.add_row(
            Text(node_id),
            Text(str(outcome)),
            "",
            "",
        )
    out.print(table)
    for note in plan.notes:
        out.print(Text(note, style="yellow"))
    for node_id, node_plan in plan.plans.items():
        if node_plan.diff:
            out.print(Text(f"{node_id}:", style="bold"))
            out.print(Text(node_plan.diff))


def show_run_notes(report: DeployReport) -> None:
    """Orrery result, apply-time notes and provision hint in yellow on stdout."""

    if report.orrery is not None:
        console.print(Text(f"orrery topology: {report.orrery}", style="yellow"))
    for note in report.notes:
        console.print(Text(note, style="yellow"))
    missing = [node_id for node_id, outcome in report.outcomes.items() if outcome == PREREQUISITE]
    if missing:
        console.print(
            Text(
                f"xray is not installed on {', '.join(missing)}: "
                f"provision first (arium fleet provision --limit {','.join(missing)}), then deploy",
                style="yellow",
            )
        )


def report_json(report: DeployReport) -> dict[str, Any]:
    """`--json` document: plan per node, plan and apply-time notes, outcomes, Orrery and notification results, log."""

    plan = report.plan
    return {
        "run_id": plan.run_id,
        "commit": plan.commit,
        "via": plan.via,
        "applied": report.applied,
        "notes": [*plan.notes, *report.notes],
        "plan": {
            node_id: {
                "config": node_plan.config is not None,
                "haproxy": node_plan.haproxy is not None,
                "xray": node_plan.binary.label if node_plan.binary else None,
                "diff": node_plan.diff,
            }
            for node_id, node_plan in plan.plans.items()
        },
        "outcomes": outcomes_json(report.outcomes),
        "orrery": report.orrery,
        "notified": report.notified,
        "log": str(report.log_path),
    }


class RolloutComponent(BaseComponent["AstrariumApp", RolloutController]):
    """`arium fleet deploy`."""

    name = "rollout"
    controller_class = RolloutController

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
            "--canary",
            metavar="ID",
            help="Node applied alone first, soaked, then re-verified.",
        )
        @click.option(
            "--canary-wait",
            type=click.FloatRange(min=0),
            default=30.0,
            show_default=True,
            help="Canary soak (s).",
        )
        @click.option(
            "--stagger",
            type=click.FloatRange(min=0),
            default=10.0,
            show_default=True,
            help="Pause between nodes of one region (s).",
        )
        @click.option(
            "--force",
            is_flag=True,
            help="Swap even when live files are identical (main@sha binaries only with --artifact).",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            help="Stop after the plan.",
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
            help="Print plan and results as JSON.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            help="SSH path (default: jump when control.jump is set).",
        )
        @click.option(
            "--artifact",
            "artifacts",
            multiple=True,
            metavar="ARCH=PATH",
            help="xray built for a main@<sha> pin.",
        )
        @click.option(
            "--rotate-exit-keys",
            is_flag=True,
            help="New keys for selected exits, deploy exits, then every hub.",
        )
        @click.option(
            "--allow-dirty",
            is_flag=True,
            help="Deploy with uncommitted changes in guarded paths.",
        )
        @click.option(
            "--notify",
            type=click.Choice(["discord"]),
            help="Send the run summary.",
        )
        @click.pass_obj
        def deploy(
            app: AstrariumApp,
            limit: str | None,
            canary: str | None,
            canary_wait: float,
            stagger: float,
            force: bool,
            dry_run: bool,
            yes: bool,
            as_json: bool,
            via: str | None,
            artifacts: tuple[str, ...],
            rotate_exit_keys: bool,
            allow_dirty: bool,
            notify: str | None,
        ) -> None:
            """Roll out xray and HAProxy configs and xray binary."""

            opts = DeployOptions(
                limit=none_if_blank(limit),
                canary=none_if_blank(canary),
                canary_wait=canary_wait,
                stagger=stagger,
                force=force,
                dry_run=dry_run,
                via=cast(Via | None, via),
                artifacts=parse_artifact_options(artifacts),
                rotate_exit_keys=rotate_exit_keys,
                allow_dirty=allow_dirty,
                notify=notify == "discord",
            )

            def confirm(plan: DeployPlan) -> bool:
                if not as_json:
                    show_plan(plan)
                if dry_run or yes or not plan.plans:
                    return True
                if not sys.stdin.isatty():
                    raise UsageProblem("confirmation needs a terminal", hint="pass --yes")
                if as_json:
                    show_plan(plan, err)
                return click.confirm(
                    "Apply this plan?",
                    default=False,
                    err=True,
                )

            report = asyncio.run(app.rollout.run(opts, confirm=confirm))
            if as_json:
                click.echo(json.dumps(report_json(report), indent=2))
            else:
                console.print(render_table(report.outcomes))
                show_run_notes(report)
                console.print(Text(f"run log: {report.log_path}", style="dim"))
            if not dry_run and not report.applied:
                raise Declined("deploy declined", hint="re-run and confirm to apply")
            code = run_exit_code(report.outcomes)
            if code is ExitCode.REFUSED:
                raise Refused("live state changed after planning", hint="run deploy again to re-plan")
            if code is ExitCode.PARTIAL:
                bad = sum(o.status in (Status.FAILED, Status.NOT_ATTEMPTED) for o in report.outcomes.values())
                raise PartialFailure(f"{bad} node(s) failed or were not attempted", hint=f"details: {report.log_path}")
