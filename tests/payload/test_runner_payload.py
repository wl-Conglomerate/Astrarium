"""Runner driving real payload through local transport (fake node, no SSH)."""

import asyncio
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

import pytest

from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.plan import NodePlan
from astrarium.components.rollout.probe import LiveState
from astrarium.components.rollout.runner import ApplyParams, apply_node
from astrarium.components.rollout.transport import CommandResult
from tests.support.payload_node import COMMIT, FakeNode


pytestmark = pytest.mark.payload


class LocalTransport:
    """Runs commands with local bash in fake node environment instead of ssh."""

    def __init__(self, node: FakeNode) -> None:
        self.node = node

    async def run(
        self,
        node_id: str,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        argv = [
            "bash",
            "-c",
            command,
        ]
        done = subprocess.run(
            argv,
            input=stdin,
            env=self.node.env,
            capture_output=True,
            timeout=timeout,
        )
        return CommandResult(
            done.returncode,
            done.stdout.decode(),
            done.stderr.decode(),
        )

    async def upload(self, node_id: str, files: Mapping[str, Path], remote_dir: str) -> CommandResult:
        for name, source in files.items():
            shutil.copyfile(source, Path(remote_dir) / name)
        return CommandResult(
            0,
            "",
            "",
        )


def test_runner_drives_real_payload_end_to_end(node: FakeNode, tmp_path) -> None:
    node.config.write_text('{"old": true}\n')
    rendered = tmp_path / "config.json"
    rendered.write_text('{"new": true}\n')
    live = node.params()
    before = LiveState(
        live["CONFIG_BEFORE"],
        None,
        live["XRAY_BEFORE"],
        "1a2b3c4",
        None,
        None,
    )
    plan = NodePlan(
        "nlA00",
        before,
        rendered,
        None,
        None,
        False,
        False,
        "",
    )
    params = ApplyParams(
        run_id="20260925T120000Z-abc123",
        commit=COMMIT,
        settle=0,
        force=False,
        deploy_user="deploy",
    )

    outcome = asyncio.run(
        apply_node(
            LocalTransport(node),
            plan,
            params,
        )
    )

    assert outcome == Outcome(Status.OK)
    assert node.config.read_text() == '{"new": true}\n'
