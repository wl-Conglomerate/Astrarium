"""CLI: `arium repo check`, plus `ci` group."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape

from astrarium.components.check.controller import BuildScope, CheckController, CheckFailed, CheckOptions, machine_arch
from astrarium.components.check.report import report_json, skip_reasons, summary_table
from astrarium.components.check.runners import DEFAULT_HAPROXY_IMAGE
from astrarium.components.rollout.artifacts import parse_artifact_options
from astrarium.components.rollout.selection import none_if_blank
from astrarium.core import BaseComponent, command_group, console


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp
    from astrarium.components.manifest.models import Arch


class CheckComponent(BaseComponent["AstrariumApp", CheckController]):
    """`arium repo check` and CI helpers."""

    name = "check"
    controller_class = CheckController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        """Register `check` and `ci` group."""

        @command_group(
            base,
            "repo",
            "Deployment repo: create, validate and test it.",
        ).command("check")
        @click.option(
            "--base",
            "base_ref",
            default="origin/main",
            show_default=True,
            help="Base ref; compared from its merge-base with HEAD.",
        )
        @click.option(
            "--report-md",
            type=click.Path(dir_okay=False, path_type=Path),
            help="Write markdown report (PR comment body).",
        )
        @click.option(
            "--xray-bin",
            type=click.Path(
                exists=True,
                dir_okay=False,
                path_type=Path,
            ),
            help="Test every config with this xray instead of pinned one.",
        )
        @click.option(
            "--artifact",
            "artifacts",
            multiple=True,
            metavar="ARCH=PATH",
            help="xray built for a main@<sha> pin; repeatable.",
        )
        @click.option(
            "--haproxy-bin",
            type=click.Path(
                exists=True,
                dir_okay=False,
                path_type=Path,
            ),
            help="Local haproxy binary for haproxy -c.",
        )
        @click.option(
            "--haproxy-image",
            help=f"Container image for haproxy -c; default {DEFAULT_HAPROXY_IMAGE}.",
        )
        @click.option(
            "--geo-dir",
            type=click.Path(
                exists=True,
                file_okay=False,
                path_type=Path,
            ),
            help="Directory holding geoip.dat and geosite.dat (skips download).",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print report as JSON.",
        )
        @click.pass_obj
        def check(
            app: AstrariumApp,
            base_ref: str,
            report_md: Path | None,
            xray_bin: Path | None,
            artifacts: tuple[str, ...],
            haproxy_bin: Path | None,
            haproxy_image: str | None,
            geo_dir: Path | None,
            as_json: bool,
        ) -> None:
            """Build base and head with throwaway keys, test head configs, report what changes."""

            opts = CheckOptions(
                base=base_ref,
                report_md=report_md,
                xray_bin=xray_bin,
                artifacts=parse_artifact_options(artifacts),
                haproxy_bin=haproxy_bin,
                haproxy_image=none_if_blank(haproxy_image) or DEFAULT_HAPROXY_IMAGE,
                geo_dir=geo_dir,
            )
            report = app.check.run(opts)
            if as_json:
                click.echo(json.dumps(report_json(report), indent=2))
            else:
                console.print(summary_table(report))
                for warning in report.warnings:
                    console.print(f"[yellow]warning:[/] {escape(warning)}")
                for reason, tests in skip_reasons(report).items():
                    console.print(f"[dim]skipped {escape(', '.join(tests))}:[/] {escape(reason)}")
                for failure in report.failures:
                    console.print(f"[red]{failure.node_id} {failure.kind}:[/] {escape(failure.detail)}")
            if report.failed:
                raise CheckFailed(f"{len(report.failures)} check test(s) failed")

        @base.group("ci")
        def ci() -> None:
            """Helpers called by deployment repo workflows."""

        @ci.command("xray-builds")
        @click.option(
            "--for",
            "scope",
            type=click.Choice(["check", "deploy"]),
            required=True,
            help="check: runner arch only; deploy: every node arch.",
        )
        @click.option(
            "--runner-arch",
            type=click.Choice(["x86_64", "aarch64"]),
            help="Arch of check runner (default: this machine).",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print compact JSON list for a workflow matrix.",
        )
        @click.pass_obj
        def xray_builds(app: AstrariumApp, scope: BuildScope, runner_arch: Arch | None, as_json: bool) -> None:
            """List xray HEAD builds (main@<sha> pins) CI must compile."""

            builds = app.check.xray_builds(scope, runner_arch if runner_arch is not None else machine_arch())
            if as_json:
                click.echo(json.dumps([asdict(build) for build in builds]))
                return
            for build in builds:
                console.print(f"{build.sha} {build.arch} ({build.goarch})")
