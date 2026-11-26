"""Deploy orchestration with fake topology and scripted transport."""

import asyncio
from typing import Any, cast

import pytest

from astrarium.components.rollout import transport
from astrarium.components.rollout.controller import RolloutController
from astrarium.components.rollout.outcomes import RECORDED_COMMIT_UNKNOWN, Outcome, Status
from astrarium.errors import Refused, UsageProblem
from tests.support.deployment import fixture_app, git, make_deployment
from tests.support.fake_transport import FakeTransport, ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import CONFIG_SHA, options, rollout_env, wire_fakes


pytestmark = pytest.mark.component


def fleet():
    return {
        "nlA00": make_node(
            "nlA00",
            role="exit",
            ipv4="203.0.113.10",
        ),
        "mskA10": make_node(
            "mskA10",
            role="hub",
            ipv4="203.0.113.20",
        ),
    }


def launches(env, node_id: str) -> int:
    return len(env.transport.commands(node_id, " launch "))


@pytest.fixture(autouse=True)
def laptop(monkeypatch) -> None:
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(
        transport,
        "RETRY_DELAY",
        0.0,
    )


def test_dirty_tree_blocks_apply_but_not_dry_run(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )
    (env.repo.root / "astrarium.yaml").write_text("deployment: {name: changed}\n")

    with pytest.raises(Refused):
        asyncio.run(env.controller.run(options(dry_run=False)))
    report = asyncio.run(env.controller.run(options(dry_run=True)))

    assert report.applied is False


def test_dry_run_plans_without_touching_nodes(tmp_path) -> None:
    live = ScriptedNode(config_text='{"log": {"loglevel": "debug"}}\n')
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": live, "mskA10": ScriptedNode(config_sha=CONFIG_SHA)},
    )

    report = asyncio.run(env.controller.run(options(dry_run=True)))

    assert report.outcomes["mskA10"] == Outcome(Status.UNCHANGED)
    assert report.outcomes["nlA00"].status is Status.OK
    assert report.plan.plans["nlA00"].diff
    assert not env.transport.commands("nlA00", "mktemp")
    assert not env.transport.commands("mskA10", "cat -- ")


def test_unreachable_node_fails_while_others_apply(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(unreachable=True), "mskA10": ScriptedNode()},
    )

    outcomes = asyncio.run(env.controller.deploy(options()))

    assert outcomes == {"nlA00": Outcome(Status.FAILED, "unreachable"), "mskA10": Outcome(Status.OK)}


def test_node_deployed_from_unrelated_commit_is_not_touched(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )
    root = env.repo.root
    ancestor = git(
        root,
        "rev-parse",
        "HEAD",
    )
    git(
        root,
        "switch",
        "-q",
        "-c",
        "side",
    )
    git(
        root,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "side",
    )
    unrelated = git(
        root,
        "rev-parse",
        "HEAD",
    )
    git(
        root,
        "switch",
        "-q",
        "main",
    )
    git(
        root,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "next",
    )
    env.transport.nodes["nlA00"].commit = unrelated
    env.transport.nodes["mskA10"].commit = ancestor

    outcomes = asyncio.run(env.controller.deploy(options()))

    assert outcomes["nlA00"] == Outcome(Status.FAILED, "older commit")
    assert outcomes["mskA10"] == Outcome(Status.OK)
    assert launches(env, "nlA00") == 0


def test_recorded_commit_unknown_locally_fails_only_that_node(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )
    env.transport.nodes["nlA00"].commit = "a" * 40

    report = asyncio.run(env.controller.run(options()))

    assert report.outcomes == {"nlA00": RECORDED_COMMIT_UNKNOWN, "mskA10": Outcome(Status.OK)}
    assert report.plan.notes
    assert launches(env, "nlA00") == 0


def test_head_pin_without_artifact_is_refused_before_any_change(tmp_path) -> None:
    nodes = fleet()
    nodes["nlA00"] = make_node("nlA00", versions={"xray": "main@" + "a" * 40})
    env = rollout_env(
        tmp_path,
        nodes,
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )

    with pytest.raises(Refused):
        asyncio.run(env.controller.run(options()))
    assert not env.transport.commands("mskA10", "mktemp")


def test_forced_head_pin_on_matching_build_swaps_config_without_artifact(tmp_path) -> None:
    build = "a" * 40
    nodes = fleet()
    nodes["nlA00"] = make_node("nlA00", versions={"xray": f"main@{build}"})
    version = f"Xray 26.3.27 (Xray, Penetrates Everything.) {build} (go1.25.1 linux/amd64)"
    live = ScriptedNode(config_sha=CONFIG_SHA, version=version)
    env = rollout_env(
        tmp_path,
        nodes,
        {"nlA00": live, "mskA10": ScriptedNode()},
    )

    report = asyncio.run(
        env.controller.run(
            options(
                limit="nlA00",
                force=True,
                dry_run=True,
            )
        )
    )

    node_plan = report.plan.plans["nlA00"]
    assert node_plan.config is not None
    assert node_plan.binary is None


def test_declined_confirmation_applies_nothing(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )

    report = asyncio.run(env.controller.run(options(), confirm=lambda plan: False))

    assert report.applied is False
    assert launches(env, "nlA00") == launches(env, "mskA10") == 0


def test_canary_failing_at_plan_time_stops_the_rest(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(unreachable=True), "mskA10": ScriptedNode()},
    )

    outcomes = asyncio.run(env.controller.deploy(options(canary="nlA00")))

    assert outcomes["nlA00"].status is Status.FAILED
    assert outcomes["mskA10"].status is Status.NOT_ATTEMPTED
    assert launches(env, "mskA10") == 0


def test_canary_unchanged_at_plan_time_notes_skipped_gate(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(config_sha=CONFIG_SHA), "mskA10": ScriptedNode()},
    )

    report = asyncio.run(env.controller.run(options(canary="nlA00", dry_run=True)))

    assert report.outcomes["nlA00"] == Outcome(Status.UNCHANGED)
    assert "mskA10" in report.plan.plans
    assert report.plan.notes


def test_orrery_topology_uploaded_after_apply(tmp_path) -> None:
    nodes = {
        **fleet(),
        "edge": make_node(
            "edge",
            role="bastion",
            ipv4="198.51.100.20",
        ),
    }
    extra = {"control": {"orrery": {"host": "edge", "topology_path": "/etc/orrery/topology.yaml"}}}
    env = rollout_env(
        tmp_path,
        nodes,
        {
            "nlA00": ScriptedNode(),
            "mskA10": ScriptedNode(),
            "edge": ScriptedNode(),
        },
        manifest_extra=extra,
    )

    report = asyncio.run(env.controller.run(options()))

    assert report.orrery == "updated"
    assert env.transport.commands("edge", "bash -c")


def test_notify_needs_webhook_before_any_connection(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
    )

    with pytest.raises(UsageProblem):
        asyncio.run(env.controller.run(options(notify=True)))
    assert env.transport.calls == []


def test_notify_sends_one_summary_after_apply(tmp_path) -> None:
    extra = {"notify": {"discord": {"webhook_url": "https://discord.example.net/api/webhooks/1/x"}}}
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()},
        manifest_extra=extra,
    )

    asyncio.run(env.controller.run(options(notify=True)))

    assert len(env.notify.calls) == 1
    assert env.notify.calls[0]["outcomes"]["nlA00"] == Outcome(Status.OK)


def test_dry_run_on_fixture_deployment_plans_without_touching_nodes(tmp_path) -> None:
    """Real TopologyController/HexRift build, fake transport: same dry-run contract as stub-topology tests."""

    root = make_deployment(tmp_path / "repo", git=True)
    app = fixture_app(root)
    controller = RolloutController(cast(Any, app))
    fake_transport = FakeTransport({"nlA00": ScriptedNode(), "mskA00": ScriptedNode()})
    wire_fakes(
        controller,
        fake_transport,
        lambda node_id, path: pytest.fail("dry run must not store keys"),
    )

    report = asyncio.run(controller.run(options(dry_run=True)))

    assert report.applied is False
    assert report.outcomes["nlA00"].status is Status.OK
    assert report.outcomes["mskA00"].status is Status.OK
    assert fake_transport.commands("nlA00", "mktemp") == []
    assert fake_transport.commands("mskA00", "mktemp") == []
