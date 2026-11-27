"""Probe output parsing and probe classification."""

import asyncio

import pytest

from astrarium.components.rollout import transport
from astrarium.components.rollout.outcomes import UNREACHABLE, Outcome, Status
from astrarium.components.rollout.probe import PROBE_MARKER, parse_probe, probe
from astrarium.components.rollout.transport import CommandResult


pytestmark = pytest.mark.unit

HEAD = "a" * 40


class OneReply:
    async def run(self, node_id, command, *, stdin=None, timeout=None) -> CommandResult:
        return self.result

    def __init__(self, result: CommandResult) -> None:
        self.result = result

    async def upload(self, node_id, files, remote_dir) -> CommandResult:
        raise AssertionError("probe never uploads")


def test_parses_versions_hashes_and_commit() -> None:
    out = "\n".join(
        [
            PROBE_MARKER,
            "config " + "1" * 64,
            "haproxy -",
            "xray " + "2" * 64,
            f"version Xray 26.3.27 (Xray, Penetrates Everything.) {HEAD} (go1.25.1 linux/amd64)",
            "arch x86_64",
            "commit " + "c" * 40,
        ]
    )

    live = parse_probe(out)

    assert (
        live.config_sha,
        live.haproxy_sha,
        live.xray_sha,
    ) == (
        "1" * 64,
        None,
        "2" * 64,
    )
    assert live.xray_build == HEAD
    assert (live.arch, live.recorded_commit) == ("x86_64", "c" * 40)


def test_only_block_after_last_marker_counts() -> None:
    out = f"Welcome banner\n{PROBE_MARKER}\nconfig {'1' * 64}\n{PROBE_MARKER}\nconfig -\nversion -\n"

    live = parse_probe(out)

    assert live.config_sha is None
    assert live.xray_build is None


def test_unreachable_and_broken_shells_are_outcomes(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "RETRY_DELAY",
        0.0,
    )

    lost = asyncio.run(
        probe(
            OneReply(
                CommandResult(
                    255,
                    "",
                    "",
                )
            ),
            "nlA00",
        )
    )
    broken = asyncio.run(
        probe(
            OneReply(
                CommandResult(
                    0,
                    "config abc\n",
                    "",
                )
            ),
            "nlA00",
        )
    )

    assert lost == UNREACHABLE
    assert isinstance(broken, Outcome)
    assert broken.status is Status.FAILED
