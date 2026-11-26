"""Stripped topology for Orrery and its idempotent upload script."""

import asyncio
import logging
import subprocess
from dataclasses import dataclass

import pytest
import yaml

from astrarium.components.rollout.orrery import stripped_topology, upload_script, upload_topology
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.secrets.masking import MASK, ValueMasker
from astrarium.components.topology.bridge import HexRiftNode


pytestmark = pytest.mark.component

NODES = {
    "nlA00": HexRiftNode(
        "nlA00",
        "nl",
        "exit",
        "nlA00.aphelion.example.net",
    ),
    "mskA10": HexRiftNode(
        "mskA10",
        "msk",
        "hub",
        "mskA10.perigee.example.net",
    ),
}

SECRET = "hunter2-orrery-upload-secret"


def test_topology_has_only_fields_orrery_reads() -> None:
    assert yaml.safe_load(stripped_topology(NODES)) == {
        "regions": [
            {
                "id": "nl",
                "type": "exit",
                "nodes": [{"id": "nlA00", "hostname": "nlA00.aphelion.example.net"}],
            },
            {
                "id": "msk",
                "type": "hub",
                "nodes": [{"id": "mskA10", "hostname": "mskA10.perigee.example.net"}],
            },
        ]
    }


def test_upload_script_replaces_once(tmp_path) -> None:
    target = tmp_path / "topology.yaml"
    text = stripped_topology(NODES)

    def run() -> str:
        argv = [
            "bash",
            "-c",
            upload_script(str(target), text),
        ]
        return subprocess.run(
            argv,
            input=text,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()

    assert run() == "updated"
    assert run() == "unchanged"
    assert target.read_text() == text


@dataclass
class _FailingTransport:
    """Transport stand-in whose run always reports failing exit with given stderr."""

    stderr: str

    async def run(self, node_id, command, *, stdin=None, timeout=None) -> CommandResult:
        return CommandResult(
            1,
            "",
            self.stderr,
        )

    async def upload(self, node_id, files, remote_dir) -> CommandResult:
        raise AssertionError("orrery upload never calls Transport.upload")


def test_upload_topology_logs_masked_stderr_on_failure(caplog: pytest.LogCaptureFixture) -> None:
    masker = ValueMasker()
    masker.add(SECRET)
    transport = _FailingTransport(stderr=f"permission denied writing topology: {SECRET}")

    with caplog.at_level(logging.WARNING, logger="astrarium.components.rollout.orrery"):
        result = asyncio.run(
            upload_topology(
                transport,
                "edge",
                "/srv/topology.yaml",
                "regions: []\n",
                masker,
            )
        )

    assert result == "failed"
    assert SECRET not in caplog.text
    assert MASK in caplog.text
