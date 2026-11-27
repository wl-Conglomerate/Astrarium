"""Runner against scripted transport: uploads, relaunch rules, reconnect classification."""

import asyncio
from pathlib import Path

import pytest

from astrarium.components.rollout import transport
from astrarium.components.rollout.artifacts import XrayArtifact
from astrarium.components.rollout.outcomes import PAYLOAD_RESULTS, Outcome, Status
from astrarium.components.rollout.plan import NodePlan
from astrarium.components.rollout.probe import LiveState
from astrarium.components.rollout.runner import ApplyParams, apply_node, payload_args
from tests.support.fake_transport import FakeTransport, ScriptedNode


pytestmark = pytest.mark.component

PARAMS = ApplyParams(
    run_id="20260925T120000Z-abc123",
    commit="c" * 40,
    settle=3,
    force=False,
    deploy_user="github_actions",
)

BEFORE = LiveState(
    "1" * 64,
    None,
    "2" * 64,
    "1a2b3c4",
    "e" * 40,
    "x86_64",
)


@pytest.fixture(autouse=True)
def no_backoff(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "RETRY_DELAY",
        0.0,
    )


def node_plan(tmp_path: Path, *, binary: XrayArtifact | None = None) -> NodePlan:
    config = tmp_path / "config.json"
    config.write_text("{}")
    return NodePlan(
        "nlA00",
        BEFORE,
        config,
        None,
        binary,
        False,
        False,
        "",
    )


def apply(fake: ScriptedNode, plan: NodePlan) -> tuple[Outcome, FakeTransport]:
    t = FakeTransport({"nlA00": fake})
    return asyncio.run(
        apply_node(
            t,
            plan,
            PARAMS,
        )
    ), t


def test_applied_uploads_payload_and_changed_files_only(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(), node_plan(tmp_path))

    assert outcome == Outcome(Status.OK)
    assert t.uploads[0][1] == ["apply.sh", "config.json"]


def test_apply_is_retried_once_when_no_swap_happened(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(verdicts=["pending", "applied"]), node_plan(tmp_path))

    assert outcome == Outcome(Status.OK)
    assert len(t.commands("nlA00", " launch ")) == 2


def test_repeated_no_swap_ends_unknown(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(verdicts=["pending", "pending"]), node_plan(tmp_path))

    assert outcome == Outcome(Status.FAILED, "unknown state")
    assert len(t.commands("nlA00", " launch ")) == 2


def test_missing_payload_at_reconcile_relaunches(tmp_path) -> None:
    _, t = apply(ScriptedNode(reconcile_rc=127), node_plan(tmp_path))

    assert len(t.commands("nlA00", " launch ")) == 2


def test_locked_launch_removes_stage_without_reconcile(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(launch_stdout="result=locked\n"), node_plan(tmp_path))

    assert outcome == PAYLOAD_RESULTS["locked"]
    stage = t.uploads[0][2]
    assert [cmd for cmd in t.commands("nlA00", "rm -rf") if stage in cmd]
    assert not t.commands("nlA00", " reconcile ")


def test_dropped_launch_is_classified_from_node_state(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(launch_rc=255, verdicts=["rolled_back"]), node_plan(tmp_path))

    assert outcome == Outcome(Status.FAILED, "rolled back")
    assert len(t.commands("nlA00", " launch ")) == 1


def test_unreachable_after_launch_is_unknown_and_never_relaunched(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(reconcile_rc=255), node_plan(tmp_path))

    assert outcome == Outcome(Status.FAILED, "unknown state")
    assert len(t.commands("nlA00", " launch ")) == 1
    assert len(t.commands("nlA00", " reconcile ")) == 3


def test_failed_upload_removes_stage(tmp_path) -> None:
    outcome, t = apply(ScriptedNode(upload_rc=1), node_plan(tmp_path))

    assert outcome == Outcome(Status.FAILED, "upload")
    assert t.commands("nlA00", "rm -rf")
    assert not t.commands("nlA00", " launch ")


def test_payload_args_carry_planned_state(tmp_path) -> None:
    head = f"main@{'d' * 40}"
    binary = XrayArtifact(
        "x86_64",
        tmp_path / "xray",
        "3" * 64,
        head,
    )
    args = payload_args(node_plan(tmp_path, binary=binary), PARAMS)

    assert f"CONFIG_BEFORE={'1' * 64}" in args
    assert f"EXPECT_COMMIT={'e' * 40}" in args
    assert f"XRAY_NEW={'3' * 64}" in args
    assert f"XRAY_EXPECT=build:{'d' * 40}" in args
    assert "HAPROXY_NEW=-" in args
