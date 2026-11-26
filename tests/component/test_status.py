"""Status: reachability, built-vs-live config, missing key files, --no-config."""

import asyncio
import logging
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any, cast

import pytest

from astrarium.components.rollout import transport
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.status.controller import NodeStatus, StatusController, StatusOptions, status_exit_code
from astrarium.components.versions.probe import NO_HOST_KEYS
from astrarium.errors import ExitCode
from tests.support.fake_transport import FakeTransport, ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import CONFIG_SHA, rollout_env


pytestmark = pytest.mark.component


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "RETRY_DELAY",
        0.0,
    )


def status_of(tmp_path, monkeypatch, fakes: dict[str, ScriptedNode], *, missing=(), no_config=False):
    nodes = {
        "nlA00": make_node("nlA00"),
        "mskA10": make_node("mskA10", role="hub"),
        "mskP00": make_node("mskP00", role="pulsar"),
    }
    env = rollout_env(
        tmp_path,
        nodes,
        fakes,
    )
    built: list[list[str]] = []
    original = env.topology.build

    def build(ctx, node_ids, out_dir):
        built.append(list(node_ids))
        return original(
            ctx,
            node_ids,
            out_dir,
        )

    monkeypatch.setattr(
        env.topology,
        "build",
        build,
    )
    controller = StatusController(env.controller.app)
    controller.make_transport = lambda paths, jumped: FakeTransport(fakes)
    controller.make_keystore = lambda: cast(Any, SimpleNamespace(missing=lambda ids: [i for i in ids if i in missing]))
    return asyncio.run(
        controller.collect(
            StatusOptions(
                limit=None,
                via=None,
                no_config=no_config,
            )
        )
    ), built


def test_config_drift_and_unreachable_nodes_are_partial(tmp_path, monkeypatch) -> None:
    fakes = {
        "nlA00": ScriptedNode(config_sha=CONFIG_SHA),
        "mskA10": ScriptedNode(),
        "mskP00": ScriptedNode(unreachable=True),
    }

    statuses, _ = status_of(
        tmp_path,
        monkeypatch,
        fakes,
    )

    assert (
        statuses["nlA00"].config,
        statuses["mskA10"].config,
        statuses["mskP00"].config,
    ) == (
        "match",
        "differs",
        "-",
    )
    assert statuses["mskP00"].reachable is False
    assert status_exit_code(statuses) is ExitCode.PARTIAL


def test_missing_exit_key_is_reported_without_building_hubs(tmp_path, monkeypatch) -> None:
    fakes = {
        "nlA00": ScriptedNode(),
        "mskA10": ScriptedNode(config_sha=CONFIG_SHA),
        "mskP00": ScriptedNode(),
    }

    statuses, built = status_of(
        tmp_path,
        monkeypatch,
        fakes,
        missing=("nlA00",),
    )

    assert "key file" in statuses["nlA00"].config
    assert "key file" in statuses["mskA10"].config
    assert built == []


def test_no_config_skips_builds(tmp_path, monkeypatch) -> None:
    fakes = {
        "nlA00": ScriptedNode(),
        "mskA10": ScriptedNode(),
        "mskP00": ScriptedNode(),
    }

    statuses, built = status_of(
        tmp_path,
        monkeypatch,
        fakes,
        no_config=True,
    )

    assert built == []
    assert status_exit_code(statuses) is ExitCode.OK


def keyless_status(tmp_path, limit: str | None) -> dict[str, NodeStatus]:
    nodes = {
        "nlA00": make_node("nlA00"),
        "nlA01": make_node("nlA01", host_keys={}),
        "mskP00": make_node(
            "mskP00",
            role="pulsar",
            host_keys={},
        ),
    }
    fakes = {"nlA00": ScriptedNode(config_sha=CONFIG_SHA)}
    env = rollout_env(
        tmp_path,
        nodes,
        fakes,
    )
    controller = StatusController(env.controller.app)
    controller.make_transport = lambda paths, jumped: FakeTransport(fakes)
    controller.make_keystore = lambda: cast(Any, SimpleNamespace(missing=lambda ids: []))
    return asyncio.run(
        controller.collect(
            StatusOptions(
                limit=limit,
                via=None,
                no_config=False,
            )
        )
    )


def test_keyless_node_is_reported_without_ssh_scope_or_failing_the_command(tmp_path) -> None:
    statuses = keyless_status(tmp_path, None)

    assert statuses["nlA01"].config == NO_HOST_KEYS
    assert statuses["nlA00"].versions
    assert statuses["nlA01"].versions == {"xray": NO_HOST_KEYS}
    assert "xray" not in statuses["mskP00"].versions
    assert status_exit_code(statuses) is ExitCode.PARTIAL


def test_keyless_node_version_cells_need_no_probed_node(tmp_path) -> None:
    statuses = keyless_status(tmp_path, "nlA01")

    assert statuses["nlA01"].versions == {"xray": NO_HOST_KEYS}


@dataclass
class _FailingProbeTransport:
    """Transport stand-in whose probe command always fails, unlike FakeTransport's scripted-only rc 0/255."""

    async def run(self, node_id, command, *, stdin=None, timeout=None) -> CommandResult:
        if "@@astrarium " in command:
            return CommandResult(
                0,
                "",
                "",
            )
        return CommandResult(
            1,
            "",
            "boom",
        )

    async def upload(self, node_id, files, remote_dir) -> CommandResult:
        raise AssertionError("status never uploads")


def test_probe_failure_reason_is_logged_not_dropped(tmp_path, caplog) -> None:
    env = rollout_env(
        tmp_path,
        {"nlA00": make_node("nlA00")},
        {},
    )
    controller = StatusController(env.controller.app)
    controller.make_transport = lambda paths, jumped: _FailingProbeTransport()
    controller.make_keystore = lambda: cast(Any, SimpleNamespace(missing=lambda ids: []))

    with caplog.at_level(logging.WARNING, logger="astrarium.components.status.controller"):
        statuses = asyncio.run(
            controller.collect(
                StatusOptions(
                    limit=None,
                    via=None,
                    no_config=False,
                )
            )
        )

    assert statuses["nlA00"].config == "unknown"
    assert statuses["nlA00"].reachable is True
    assert statuses["nlA00"].mismatches == ["config"]
    assert any(
        record.name == "astrarium.components.status.controller"
        and record.levelno == logging.WARNING
        and "nlA00" in record.getMessage()
        for record in caplog.records
    )
