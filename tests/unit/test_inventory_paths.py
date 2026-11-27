"""Identities, routes and deploy lock check outcomes."""

from __future__ import annotations

import asyncio
import logging

import pytest

from astrarium.components.inventory.paths import check_cast_identity, deploy_busy, paths_in_use
from astrarium.components.rollout.outcomes import Status
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.secrets.masking import MASK, ValueMasker
from astrarium.errors import Refused, UsageProblem
from tests.support.fleet import ScriptedTransport, make_control


pytestmark = pytest.mark.unit


def test_ci_casts_need_cast_keys_and_the_jump_route():
    with pytest.raises(Refused):
        check_cast_identity(
            "ci",
            "direct",
            make_control(),
        )
    with pytest.raises(UsageProblem):
        check_cast_identity(
            "ci",
            "jump",
            make_control(ci=False),
        )
    check_cast_identity(
        "admin",
        "direct",
        make_control(ci=False),
    )


def test_paths_in_use_cover_deploy_and_cast_identity_on_every_used_route():
    assert set(
        paths_in_use(
            "admin",
            "direct",
            make_control(),
        )
    ) == {
        ("deploy", "direct"),
        ("deploy", "jump"),
        ("admin", "direct"),
        ("admin", "jump"),
    }
    assert set(
        paths_in_use(
            "ci",
            "jump",
            make_control(),
        )
    ) == {("deploy", "jump"), ("ci", "jump")}
    assert set(
        paths_in_use(
            "admin",
            "direct",
            make_control(jump=None, ci=False),
        )
    ) == {
        ("deploy", "direct"),
        ("admin", "direct"),
    }
    assert set(
        paths_in_use(
            "root",
            "direct",
            make_control(),
        )
    ) == {
        ("deploy", "direct"),
        ("deploy", "jump"),
    }
    assert set(
        paths_in_use(
            "root",
            "jump",
            make_control(),
        )
    ) == {("deploy", "jump")}


def test_deploy_lock_holders_are_left_not_attempted_and_silent_nodes_fail():
    transport = ScriptedTransport(
        replies={
            ("nlA00", "flock"): CommandResult(
                rc=75,
                stdout="",
                stderr="",
            ),
            ("nlA01", "flock"): CommandResult(
                rc=255,
                stdout="",
                stderr="on github_actions: no such lock",
            ),
        }
    )

    blocked = asyncio.run(
        deploy_busy(
            transport,
            [
                "nlA00",
                "nlA01",
                "mskA10",
            ],
            "github_actions",
            ValueMasker(),
        )
    )

    assert blocked["nlA00"].status is Status.NOT_ATTEMPTED
    assert blocked["nlA01"].status is Status.FAILED
    assert "mskA10" not in blocked


def test_deploy_busy_logs_rc_and_masks_registered_secrets_out_of_the_dropped_stderr(caplog):
    transport = ScriptedTransport(
        replies={
            ("nlA01", "flock"): CommandResult(
                rc=1,
                stdout="",
                stderr="sudo: token deadbeef1234 rejected",
            )
        }
    )
    masker = ValueMasker()
    masker.add("deadbeef1234")

    with caplog.at_level(logging.WARNING):
        blocked = asyncio.run(
            deploy_busy(
                transport,
                ["nlA01"],
                "github_actions",
                masker,
            )
        )

    assert blocked["nlA01"].status is Status.FAILED
    assert "1" in (blocked["nlA01"].reason or "")
    assert "deadbeef1234" not in caplog.text
    assert MASK in caplog.text
    assert "nlA01" in caplog.text
