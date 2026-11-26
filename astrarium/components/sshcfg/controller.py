"""SSH sessions through generated config (`arium fleet ssh`)."""

from __future__ import annotations

import subprocess
from typing import TYPE_CHECKING

from astrarium.components.manifest.models import Identity
from astrarium.components.sshcfg.render import Via, resolve_via, ssh_scope, write_ssh_files
from astrarium.core import BaseController
from astrarium.errors import UsageProblem
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class SshController(BaseController["AstrariumApp"]):
    """Interactive or one-shot ssh over generated files."""

    def session(self, node_id: str, command: list[str], *, identity: Identity, via: Via | None) -> int:
        """Prepare, render ssh files for node (plus jump), run ssh with prompts allowed, return its exit code.

        need_keys=False skips node key files (secrets/keys), host keys come from manifest.
        Runtime dir (config, known_hosts) removed when ssh exits.
        """

        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            if node_id not in ctx.nodes:
                raise UsageProblem(f"unknown node {node_id}")
            control = ctx.manifest.control
            route = resolve_via(control, via)
            scope = ssh_scope(
                ctx.nodes,
                [node_id],
                control,
                route,
            )
            paths = write_ssh_files(
                runtime,
                scope,
                control,
                identity,
                route,
            )
            argv = [
                "ssh",
                "-F",
                str(paths.config),
                "-o",
                "BatchMode=no",
                "--",
                node_id,
                *command,
            ]
            return subprocess.call(argv)  # noqa: S603
