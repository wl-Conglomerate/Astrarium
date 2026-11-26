"""CLI: `arium repo init`."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click
from rich.markup import escape

from astrarium.components.init.controller import InitController, InitOptions, InitResult
from astrarium.core import command_group, console
from astrarium.core.component import BaseComponent


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp

LOCK_STEP = """
  uv lock --directory {dest} with photon credentials (UV_INDEX_PHOTON_USERNAME=__token__, UV_INDEX_PHOTON_PASSWORD):
  CI runs `uv sync --frozen`, which fails without uv.lock"""

NEXT_STEPS = """
  git -C {dest} init -b main && git -C {dest} add -A && git -C {dest} commit -m "chore: init deployment"
  add nodes to astrarium.yaml and topology.yaml, then: arium keys gen, arium versions bump xray <tag>, arium repo doctor
  GitHub: repository secret PHOTON_READ_TOKEN; environment "production" (deployment branch policy: main)
  with SOPS_AGE_KEY and ASTRARIUM_DEPLOY_SSH_KEY. Deploys stay off until variable ASTRARIUM_DEPLOY=enabled;
  CI casts need ASTRARIUM_CAST_SSH_KEY and ASTRARIUM_CI_CAST=enabled."""

DNS_STEP = """
  DNS: repository secret CLOUDFLARE_DNS_READ_TOKEN (PR plan), environment "production" secret CLOUDFLARE_API_TOKEN;
  DNS deploys stay off until variable ASTRARIUM_DNS_DEPLOY=enabled."""


def next_steps(result: InitResult) -> str:
    """Steps after init: `uv lock` when skipped, commit, GitHub secrets and variables (DNS ones for DNS repos)."""

    steps = (LOCK_STEP if not result.locked else "") + NEXT_STEPS + (DNS_STEP if result.has_dns else "")
    return "Next steps:" + steps.format(dest=result.dest)


class InitComponent(BaseComponent["AstrariumApp", InitController]):
    """`arium repo init`."""

    name = "init"
    controller_class = InitController

    @classmethod
    def expose_cli(cls, base: click.Group) -> None:
        """Register `init`."""

        @command_group(
            base,
            "repo",
            "Deployment repo: create, validate and test it.",
        ).command("init")
        @click.argument(
            "dest",
            type=click.Path(file_okay=False, path_type=Path),
        )
        @click.option(
            "--name",
            "deployment_name",
            help="Deployment name (lowercase letters, digits, dashes).",
        )
        @click.option(
            "--domain",
            help="Fleet domain.",
        )
        @click.option(
            "--jump",
            help="Node id of SSH jump host.",
        )
        @click.option(
            "--photon-url",
            help="Photon index URL (https://.../simple/).",
        )
        @click.option(
            "--recipient",
            "recipients",
            multiple=True,
            help="sops recipient (age1... or ssh-ed25519 ...); repeatable.",
        )
        @click.option(
            "--dns/--no-dns",
            "has_dns",
            default=None,
            help="Manage DNS zones with Manticora under dns/.",
        )
        @click.option(
            "--manticora-version",
            help="Manticora release to pin when DNS is managed.",
        )
        @click.option(
            "--template",
            default=None,
            help="Render a different Copier template (git URL or local path) instead.",
        )
        @click.option(
            "--vcs-ref",
            help="Git ref of an external --template (git URL only).",
        )
        @click.option(
            "--defaults",
            is_flag=True,
            help="Never prompt; defaults for unanswered questions.",
        )
        @click.option(
            "--skip-lock",
            is_flag=True,
            help="Skip `uv lock` (run it later with photon credentials).",
        )
        @click.option(
            "--trust",
            is_flag=True,
            help="Allow unsafe features (Jinja extensions) from a non-default --template.",
        )
        @click.option(
            "--json",
            "as_json",
            is_flag=True,
            help="Print result as JSON.",
        )
        @click.pass_obj
        def init(
            app: AstrariumApp,
            dest: Path,
            deployment_name: str | None,
            domain: str | None,
            jump: str | None,
            photon_url: str | None,
            recipients: tuple[str, ...],
            has_dns: bool | None,
            manticora_version: str | None,
            template: str,
            vcs_ref: str | None,
            defaults: bool,
            skip_lock: bool,
            trust: bool,
            as_json: bool,
        ) -> None:
            """Create deployment repo from Astrarium template."""

            given = {
                "deployment_name": deployment_name,
                "domain": domain,
                "jump": jump,
                "photon_url": photon_url,
                "age_recipients": "\n".join(recipients) if recipients else None,
                "has_dns": has_dns,
                "manticora_version": manticora_version,
            }
            opts = InitOptions(
                dest=dest,
                answers={key: value for key, value in given.items() if value is not None},
                template=template,
                vcs_ref=vcs_ref,
                defaults=defaults,
                run_tasks=not skip_lock,
                quiet=as_json,
                trust=trust,
            )
            result = app.init.init(opts)
            if as_json:
                click.echo(json.dumps({"dest": str(result.dest), "files": result.files}, indent=2))
                return
            console.print(f"[green]Created[/] {escape(str(result.dest))} ({len(result.files)} files)")
            console.print(escape(next_steps(result)))
