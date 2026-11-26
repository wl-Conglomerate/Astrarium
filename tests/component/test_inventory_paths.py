"""Fresh-login checks over run-scoped ssh files and deploy lock check script."""

from __future__ import annotations

import asyncio
import os
import subprocess

import pytest

from astrarium.components.inventory.paths import (
    LOCK_BUSY_RC,
    PATH_PROBE,
    PathFailure,
    lock_check_command,
    probe_targets,
    run_scoped_transports,
    verify_paths,
)
from astrarium.components.rollout.transport import CommandResult, write_scoped_ssh
from astrarium.runtime import RuntimeDir
from tests.support.fleet import TransportPool, fleet, make_control


pytestmark = pytest.mark.component


def test_probe_targets_never_reach_outside_this_runs_scope():
    """After jump batch: this run's whole scope (jump plus every routed target), not fleet."""

    nodes, control = fleet(), make_control()
    wanted = [
        "nlA00",
        "nlA01",
        "mskA10",
        "plsA00",
    ]
    with RuntimeDir() as runtime:
        deploy_paths, _ = write_scoped_ssh(
            runtime,
            nodes,
            control,
            "deploy",
            "jump",
            wanted=wanted,
        )
        admin_paths, _ = write_scoped_ssh(
            runtime,
            nodes,
            control,
            "admin",
            "jump",
            wanted=wanted,
        )

        assert probe_targets(
            nodes,
            deploy_paths,
            "deploy",
            ["nlA00"],
            jump_batch=False,
        ) == ["nlA00"]
        assert set(
            probe_targets(
                nodes,
                deploy_paths,
                "deploy",
                wanted,
                jump_batch=True,
            )
        ) == set(wanted)
        assert "edge" not in probe_targets(
            nodes,
            deploy_paths,
            "deploy",
            wanted,
            jump_batch=True,
        )
        assert "edge" in probe_targets(
            nodes,
            admin_paths,
            "admin",
            wanted,
            jump_batch=True,
        )


def test_verify_paths_reports_failing_identity_and_route():
    pool = TransportPool()
    pool.get("admin", "jump").replies[("nlA01", PATH_PROBE)] = CommandResult(
        rc=255,
        stdout="",
        stderr="",
    )

    with RuntimeDir() as runtime:
        open_transport = run_scoped_transports(
            runtime,
            fleet(),
            make_control(),
            pool,
            ["nlA00", "nlA01"],
        )
        failures = asyncio.run(
            verify_paths(
                open_transport,
                fleet(),
                [("deploy", "jump"), ("admin", "jump")],
                ["nlA00", "nlA01"],
                jump_batch=False,
            )
        )

    assert failures == [
        PathFailure(
            node_id="nlA01",
            identity="admin",
            via="jump",
            rc=255,
        )
    ]


def test_verify_paths_after_a_jump_batch_probes_the_runs_routed_targets_not_just_the_jump():
    """Jump batch (SSH-sensitive change on bastion) checks deploy route through it for every run target,
    deploy hop login and admin login on bastion itself, never jump host alone.
    """

    nodes, control = fleet(), make_control()
    wanted = [
        "nlA00",
        "nlA01",
        "mskA10",
        "plsA00",
    ]
    pool = TransportPool()

    with RuntimeDir() as runtime:
        open_transport = run_scoped_transports(
            runtime,
            nodes,
            control,
            pool,
            wanted,
        )
        failures = asyncio.run(
            verify_paths(
                open_transport,
                nodes,
                [("deploy", "jump"), ("admin", "jump")],
                ["edge"],
                jump_batch=True,
            )
        )

    assert failures == []
    assert {node_id for node_id, _ in pool.get("deploy", "jump").calls} == {*wanted, "edge"}
    assert "edge" in {node_id for node_id, _ in pool.get("admin", "jump").calls}


def test_run_scoped_transports_opens_each_pair_once_over_the_whole_run():
    """One write_scoped_ssh (and one transport) per (identity, via) for whole run: reopening
    same pair across batches must reuse it rather than rewrite shared config file underneath.
    """

    nodes, control = fleet(), make_control()
    wanted = ["nlA00", "nlA01"]
    pool = TransportPool()

    with RuntimeDir() as runtime:
        open_transport = run_scoped_transports(
            runtime,
            nodes,
            control,
            pool,
            wanted,
        )
        first_paths, first_transport = open_transport("deploy", "direct")
        second_paths, second_transport = open_transport("deploy", "direct")

    assert second_paths is first_paths
    assert second_transport is first_transport
    assert first_paths.nodes == frozenset(wanted)


def test_lock_check_command_fails_closed_when_sudo_is_denied(tmp_path):
    """Refused `sudo -n` (password required, no sudoers entry) must not read as lock absent."""

    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "sudo").write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    (stubs / "getent").write_text(f'#!/bin/sh\necho "deploy:x:1000:1000::{tmp_path}:/bin/bash"\n', encoding="utf-8")
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}

    rc = subprocess.run(
        [
            "sh",
            "-c",
            lock_check_command("deploy"),
        ],
        env=env,
        check=False,
    ).returncode

    assert rc not in (0, LOCK_BUSY_RC)
