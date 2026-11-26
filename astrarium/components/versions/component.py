"""`arium versions`: list, outdated, bump and apply component pins."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict
from typing import TYPE_CHECKING, cast

import rich_click as click
from rich.markup import escape

from astrarium.components.inventory.component import (
    confirmer,
    echo_masked,
    exit_for,
    print_log_tails,
    render_reports,
    reports_json,
)
from astrarium.components.rollout.selection import none_if_blank
from astrarium.components.sshcfg.render import Via
from astrarium.components.versions.controller import ApplyOptions, BumpOptions, ListOptions, VersionsController
from astrarium.components.versions.report import list_json, list_table, node_table, outdated_json, outdated_table
from astrarium.core import BaseComponent, console, err
from astrarium.errors import Declined


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp
    from astrarium.components.inventory.paths import CastIdentity


def print_warnings(warnings: list[str]) -> None:
    """Upstream lookup failures on stderr."""

    for warning in warnings:
        err.print(f"[yellow]warning:[/] {escape(warning)}")


class VersionsComponent(BaseComponent["AstrariumApp", VersionsController]):
    name = "versions"
    controller_class = VersionsController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        @base.group("versions")
        def versions_group() -> None:
            """Component versions: pins, installed versions, upstream releases."""

        @versions_group.command("list")
        @click.option(
            "--node",
            "node_id",
            help="Show one node: effective pin, layer and installed version per component.",
        )
        @click.option(
            "--all",
            "all_components",
            is_flag=True,
            help="Add every NullForge default component.",
        )
        @click.option(
            "--no-probe",
            is_flag=True,
            help="Skip the read-only SSH probe of installed versions.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            default=None,
            help="SSH route (default: jump when control.jump is set).",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Emit JSON.",
        )
        @click.pass_obj
        def list_command(
            app: AstrariumApp,
            node_id: str | None,
            all_components: bool,
            no_probe: bool,
            via: str | None,
            as_json: bool,
        ) -> None:
            """Pins and layer that set them, installed version per node, latest upstream release."""

            options = ListOptions(
                node=node_id,
                all_components=all_components,
                probe=not no_probe,
                via=cast(Via | None, via),
            )
            report = asyncio.run(app.versions.list_versions(options))
            if as_json:
                click.echo(json.dumps(list_json(report), indent=2))
            else:
                console.print(node_table(report) if report.node is not None else list_table(report))
            print_warnings(report.warnings)

        @versions_group.command("outdated")
        @click.option(
            "--pre",
            is_flag=True,
            help="Compare with prereleases too.",
        )
        @click.option(
            "--all",
            "all_components",
            is_flag=True,
            help="Add every NullForge default component.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Emit JSON.",
        )
        @click.pass_obj
        def outdated_command(app: AstrariumApp, pre: bool, all_components: bool, as_json: bool) -> None:
            """Pins behind newest upstream release, main@<sha> pins behind upstream main."""

            report = app.versions.outdated(pre=pre, all_components=all_components)
            failed = len(report.warnings)
            if as_json:
                click.echo(json.dumps(outdated_json(report), indent=2))
            else:
                if report.rows:
                    console.print(outdated_table(report))
                elif not failed:
                    console.print("All pins are current.")
                if failed:
                    console.print(f"[yellow]{failed} upstream lookup(s) failed, their pins were not compared.[/]")
            print_warnings(report.warnings)

        @versions_group.command("bump")
        @click.argument("component")
        @click.argument("version")
        @click.option(
            "--node",
            "node_id",
            help="Pin on one node (nodes.<id>.overrides.versions) instead of fleet-wide.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Emit JSON.",
        )
        @click.pass_obj
        def bump_command(app: AstrariumApp, component: str, version: str, node_id: str | None, as_json: bool) -> None:
            """Pin COMPONENT to VERSION after checking upstream.

            \b
            xray: vX.Y.Z or latest (needs assets for fleet architectures, or --node arch, plus x86_64 where
            CI check runs, sha256 recorded per architecture),
            main@<sha> or main@latest (commit must be on upstream main).
            NullForge components: release tag must exist, latest resolves to newest stable release.
            Tool stack (astrarium, hexrift, nullforge, manticora): uv add rewrites pyproject.toml and uv.lock.
            """

            result = app.versions.bump(
                BumpOptions(
                    component=component,
                    version=version,
                    node=node_id,
                )
            )
            if as_json:
                click.echo(json.dumps(asdict(result), indent=2))
                return
            where = f" on {result.node}" if result.node is not None else ""
            before = result.before if result.before is not None else "-"
            files = ", ".join(result.files)
            change = f"{escape(before)} -> [bold]{escape(result.after)}[/]"
            console.print(f"{escape(result.component)}{escape(where)}: {change} ({files})")
            err.print("Review the diff and commit it through a pull request.")

        @versions_group.command("apply")
        @click.argument(
            "component",
            required=False,
        )
        @click.option(
            "--changed-since",
            "changed_since",
            metavar="REF",
            help="Apply NullForge pins whose effective value changed since REF (CI push job).",
        )
        @click.option(
            "--limit",
            help="Comma list of node ids, regions and @role; bastions only by id.",
        )
        @click.option(
            "--canary",
            help="Node cast alone first and re-probed before the rest.",
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
            "--as",
            "identity",
            type=click.Choice(["admin", "ci"]),
            default="admin",
            show_default=True,
            help="Login identity: managed admin user (laptop) or CI cast user.",
        )
        @click.option(
            "--via",
            type=click.Choice(["direct", "jump"]),
            default=None,
            help="SSH route (default: jump when control.jump is set).",
        )
        @click.option(
            "--dry-run",
            is_flag=True,
            help="Run cast --dry --diff and report operations that would change.",
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
        def apply_command(
            app: AstrariumApp,
            component: str | None,
            changed_since: str | None,
            limit: str | None,
            canary: str | None,
            canary_wait: float,
            stagger: float,
            identity: str,
            via: str | None,
            dry_run: bool,
            yes: bool,
            as_json: bool,
            allow_dirty: bool,
            follow: bool,
        ) -> None:
            """Cast rune of NullForge-owned COMPONENT where enabled, then re-probe installed == pinned.

            \b
            xray is converged by `arium fleet deploy`, tool stack pins change with `arium versions bump`.
            """

            options = ApplyOptions(
                component=component,
                changed_since=changed_since,
                limit=none_if_blank(limit),
                canary=none_if_blank(canary),
                canary_wait=canary_wait,
                stagger=stagger,
                identity=cast("CastIdentity", identity),
                via=cast("Via | None", via),
                dry_run=dry_run,
                allow_dirty=allow_dirty,
                echo=echo_masked if follow else None,
            )
            reports = asyncio.run(app.versions.apply(options, confirmer(yes=yes, dry_run=dry_run)))
            if reports is None:
                raise Declined("versions apply declined", hint="re-run and confirm to cast")
            if as_json:
                click.echo(json.dumps({"nodes": reports_json(reports)}, indent=2))
            elif not reports:
                console.print("No NullForge pin to apply.")
            else:
                console.print(render_reports(reports))
                print_log_tails(reports)
            exit_for(reports)
