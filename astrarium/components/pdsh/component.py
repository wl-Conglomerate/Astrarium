"""CLI: `arium fleet pdsh COMMAND...`."""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Literal, cast

import rich_click as click
from rich.markup import escape

from astrarium.components.manifest.models import Identity
from astrarium.components.pdsh.controller import (
    DEFAULT_FANOUT,
    NodeResult,
    PdshController,
    PdshOptions,
    PdshReport,
    collapse_groups,
    pdsh_exit_code,
)
from astrarium.components.rollout.selection import none_if_blank
from astrarium.components.sshcfg.render import Via
from astrarium.core import BaseComponent, command_group, console, err
from astrarium.errors import UsageProblem


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


def report_json(report: PdshReport, *, collapse: bool) -> dict[str, object]:
    """JSON view: per-node results, or collapse groups when `collapse`."""

    base: dict[str, object] = {
        "command": report.command,
        "via": report.via,
        "targets": report.targets,
        "skipped": report.skipped,
    }
    if collapse:
        base["groups"] = [
            {
                "nodes": nodes,
                "rc": result.rc,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            for nodes, result in collapse_groups(report.results)
        ]
    else:
        base["results"] = [
            {
                "node": r.node_id,
                "rc": r.rc,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
            for r in report.results
        ]
    return base


def _print_lines(prefix: str, text: str, *, to_err: bool = False) -> None:
    out = err if to_err else console
    for line in text.splitlines():
        out.print(f"{escape(prefix)}: {escape(line)}")


def _print_block(head: str, result: NodeResult) -> None:
    """dshbak-style block: dashed header with host list, output lines unprefixed."""

    console.print("-" * 16)
    console.print(escape(head))
    console.print("-" * 16)
    for line in result.stdout.splitlines():
        console.print(escape(line))
    for line in result.stderr.splitlines():
        err.print(escape(line))


def _failure_lines(results: list[NodeResult]) -> None:
    """Failed nodes get closing detail block: rc plus last stderr/stdout line"""

    failed = [result for result in results if result.rc != 0]
    if not failed:
        return
    err.print(f"[red]failed ({len(failed)}):[/]")
    for result in failed:
        tail = (result.stderr or result.stdout).strip().splitlines()
        detail = tail[-1] if tail else "no output"
        err.print(f"  [red]{escape(result.node_id)}[/] rc={result.rc}: {escape(detail)}")


def render_report(report: PdshReport, *, view: Literal["lines", "blocks", "collapse"]) -> None:
    """Output views: pdsh raw `node: line`, dshbak per-node blocks, or dshbak -c coalesced blocks."""

    if not report.results:
        console.print(f"$ {escape(report.command)}")
        console.print(f"targets ({len(report.targets)}): {escape(', '.join(report.targets) or 'none')}")
        for node_id, reason in sorted(report.skipped.items()):
            err.print(f"skipped {escape(node_id)}: {escape(reason)}")
        return
    if view == "collapse":
        for nodes, result in collapse_groups(report.results):
            head = ",".join(nodes) + (f" (rc={result.rc})" if result.rc != 0 else "")
            _print_block(head, result)
    elif view == "blocks":
        for result in report.results:
            _print_block(result.node_id, result)
    else:
        for result in report.results:
            _print_lines(result.node_id, result.stdout)
            _print_lines(
                result.node_id,
                result.stderr,
                to_err=True,
            )
    _failure_lines(report.results)
    failed = sum(1 for result in report.results if result.rc != 0)
    err.print(f"[dim]{len(report.results)} node(s), {failed} failed[/]")


class PdshComponent(BaseComponent["AstrariumApp", PdshController]):
    name = "pdsh"
    controller_class = PdshController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @command_group(
            base,
            "fleet",
            "Fleet nodes: render, deploy, provision, reach and inspect.",
        ).command("pdsh", context_settings={"allow_interspersed_args": False})
        @click.option(
            "--limit",
            help="Comma list of node ids, regions and @role (union; default: every node).",
        )
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
            help="Login identity.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            help="SSH path (default: jump when control.jump is set).",
        )
        @click.option(
            "--fanout",
            type=click.IntRange(min=1),
            default=DEFAULT_FANOUT,
            show_default=True,
            help="Max concurrent ssh sessions (pdsh -f).",
        )
        @click.option(
            "--timeout",
            type=click.FloatRange(min=0),
            default=None,
            help="Per-node command timeout (s); local ssh killed on expiry, remote command may outlive it.",
        )
        @click.option(
            "--collapse",
            is_flag=True,
            help="dshbak -c style: coalesce nodes with identical output into one block.",
        )
        @click.option(
            "--blocks",
            is_flag=True,
            help="dshbak style: one dashed block per node, lines unprefixed.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print results as JSON.",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            help="Print resolved targets and command, run nothing.",
        )
        @click.argument(
            "command",
            nargs=-1,
            type=click.UNPROCESSED,
        )
        @click.pass_obj
        def pdsh(
            app: AstrariumApp,
            limit: str | None,
            identity: str,
            via: str | None,
            fanout: int,
            timeout: float | None,
            collapse: bool,
            blocks: bool,
            as_json: bool,
            dry_run: bool,
            command: tuple[str, ...],
        ) -> None:
            """Run COMMAND on every selected node in parallel (pdsh-style), options go before COMMAND."""

            if not command:
                raise UsageProblem("no command given", hint="pass remote command after options")
            if collapse and blocks:
                raise UsageProblem("--collapse and --blocks are mutually exclusive")
            view: Literal["lines", "blocks", "collapse"] = "collapse" if collapse else "blocks" if blocks else "lines"
            opts = PdshOptions(
                limit=none_if_blank(limit),
                identity=cast(Identity, identity),
                via=cast("Via | None", via),
                fanout=fanout,
                timeout=timeout,
                dry_run=dry_run,
            )
            # pdsh semantics: argv joined with spaces, remote shell parses string
            # (single quoted 'cmd args' string passes through unquoted)
            report = asyncio.run(app.pdsh.run(" ".join(command), opts))
            if as_json:
                click.echo(json.dumps(report_json(report, collapse=collapse), indent=2))
            else:
                render_report(report, view=view)
            code = pdsh_exit_code(report.results)
            if code:
                raise SystemExit(code)
