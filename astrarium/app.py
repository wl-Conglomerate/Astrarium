"""Astrarium application, root command group and global options."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

import rich_click as click
from rich.logging import RichHandler

from astrarium import __version__
from astrarium.components.check.component import CheckComponent
from astrarium.components.doctor.component import DoctorComponent
from astrarium.components.init.component import InitComponent
from astrarium.components.inventory.component import InventoryComponent
from astrarium.components.keys.component import KeysComponent
from astrarium.components.manifest.component import ManifestComponent
from astrarium.components.notify.component import NotifyComponent
from astrarium.components.pdsh.component import PdshComponent
from astrarium.components.rollout.component import RolloutComponent
from astrarium.components.secrets.component import SecretsComponent
from astrarium.components.secrets.sops import Sops
from astrarium.components.sshcfg.component import SshComponent
from astrarium.components.status.component import StatusComponent
from astrarium.components.topology.component import TopologyComponent
from astrarium.components.versions.component import VersionsComponent
from astrarium.core import BaseApplication, console, err
from astrarium.repo import Repo


if TYPE_CHECKING:
    from astrarium.components.check.controller import CheckController
    from astrarium.components.doctor.controller import DoctorController
    from astrarium.components.init.controller import InitController
    from astrarium.components.inventory.controller import InventoryController
    from astrarium.components.keys.controller import KeysController
    from astrarium.components.manifest.controller import ManifestController
    from astrarium.components.notify.controller import NotifyController
    from astrarium.components.pdsh.controller import PdshController
    from astrarium.components.rollout.controller import RolloutController
    from astrarium.components.secrets.controller import SecretsController
    from astrarium.components.sshcfg.controller import SshController
    from astrarium.components.status.controller import StatusController
    from astrarium.components.topology.controller import TopologyController
    from astrarium.components.versions.controller import VersionsController


click.rich_click.TEXT_MARKUP = "rich"

click.rich_click.SHOW_ARGUMENTS = True

click.rich_click.GROUP_ARGUMENTS_OPTIONS = True

click.rich_click.STYLE_ERRORS_SUGGESTION = "dim italic"

click.rich_click.MAX_WIDTH = 100

click.rich_click.COMMAND_GROUPS = {
    "cli": [
        {
            "name": "Repository",
            "commands": ["repo", "config"],
        },
        {
            "name": "Fleet",
            "commands": ["fleet"],
        },
        {
            "name": "Secrets and keys",
            "commands": ["secrets", "keys"],
        },
        {
            "name": "Tooling",
            "commands": [
                "versions",
                "ci",
                "hexrift",
            ],
        },
    ],
    "cli repo": [
        {
            "name": "Create",
            "commands": ["init"],
        },
        {
            "name": "Verify",
            "commands": ["check", "doctor"],
        },
    ],
    "cli fleet": [
        {
            "name": "Render and inspect",
            "commands": ["build", "status"],
        },
        {
            "name": "Change",
            "commands": ["deploy", "provision"],
        },
        {
            "name": "Access",
            "commands": ["ssh", "pdsh"],
        },
    ],
    "cli versions": [
        {
            "name": "Inspect",
            "commands": ["list", "outdated"],
        },
        {
            "name": "Change",
            "commands": ["bump", "apply"],
        },
    ],
    "cli config": [
        {
            "name": "Inspect",
            "commands": ["show"],
        },
        {
            "name": "Reference",
            "commands": ["schema"],
        },
    ],
    "cli keys": [
        {
            "name": "Create",
            "commands": ["gen"],
        },
        {
            "name": "Inspect",
            "commands": ["show"],
        },
    ],
    "cli secrets": [
        {
            "name": "Recipients",
            "commands": ["recipients"],
        },
    ],
    "cli secrets recipients": [
        {
            "name": "Change",
            "commands": ["add", "remove"],
        },
    ],
}


class AstrariumApp(BaseApplication["AstrariumApp"]):
    """Component registry, repo discovered lazily so repo-less commands (init) work anywhere."""

    default_components = (
        ManifestComponent,
        InitComponent,
        DoctorComponent,
        CheckComponent,
        TopologyComponent,
        RolloutComponent,
        InventoryComponent,
        StatusComponent,
        SshComponent,
        PdshComponent,
        SecretsComponent,
        KeysComponent,
        VersionsComponent,
        NotifyComponent,
    )

    manifest: ManifestController

    secrets: SecretsController

    topology: TopologyController

    keys: KeysController

    doctor: DoctorController

    notify: NotifyController

    rollout: RolloutController

    status: StatusController

    sshcfg: SshController

    pdsh: PdshController

    inventory: InventoryController

    versions: VersionsController

    check: CheckController

    init: InitController

    def __init__(self, repo_path: Path | None = None) -> None:
        self.repo_path = repo_path
        self._repo: Repo | None = None
        self.sops = Sops()
        super().__init__()

    @property
    def repo(self) -> Repo:
        if self._repo is None:
            self._repo = Repo.discover(self.repo_path)
        return self._repo


@click.group()
@click.version_option(
    __version__,
    "-V",
    "--version",
)
@click.option(
    "--repo",
    "repo_path",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Deployment repo (default: nearest parent holding astrarium.yaml).",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    help="Debug logging.",
)
@click.option(
    "--no-color",
    is_flag=True,
    help="Plain output without colors.",
)
@click.pass_context
def cli(ctx: click.Context, repo_path: Path | None, verbose: bool, no_color: bool) -> None:
    """Astrarium - deploy and manage Conglomerate fleets."""

    if no_color:
        console.no_color = True
        err.no_color = True
    handler = RichHandler(
        console=err,
        show_time=False,
        show_path=False,
    )
    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
        handlers=[handler],
        force=True,
    )
    logging.getLogger("astrarium").setLevel(logging.DEBUG if verbose else logging.INFO)
    ctx.obj = AstrariumApp(repo_path)


@cli.result_callback()
def _discard_result(result: object, **_params: object) -> None:
    return None


AstrariumApp.register_cli(cli)
