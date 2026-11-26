"""Exit key rotation during deploy."""

import asyncio

import pytest

from astrarium.components.rollout import transport
from astrarium.components.rollout.outcomes import Outcome, Status, run_exit_code
from astrarium.components.secrets.masking import MASK
from astrarium.errors import ExitCode, ExternalToolError, Refused
from tests.support.deployment import git
from tests.support.fake_transport import ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import options, rollout_env


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


def fakes():
    return {"nlA00": ScriptedNode(), "mskA10": ScriptedNode()}


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


def test_rotation_must_include_every_hub_and_is_laptop_only(tmp_path, monkeypatch) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        fakes(),
    )

    with pytest.raises(Refused):
        asyncio.run(env.controller.run(options(rotate_exit_keys=True, limit="nlA00")))
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with pytest.raises(Refused):
        asyncio.run(env.controller.run(options(rotate_exit_keys=True)))
    assert env.topology.keys.rotated == []


def test_rotation_stores_keys_after_confirmation_then_exits_before_hubs(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        fakes(),
    )

    dry = asyncio.run(env.controller.run(options(rotate_exit_keys=True, dry_run=True)))
    assert env.stored == []
    assert dry.plan.notes

    outcomes = asyncio.run(env.controller.deploy(options(rotate_exit_keys=True)))

    order = [node_id for node_id, command in env.transport.calls if " launch " in command]
    assert env.stored == ["nlA00"]
    assert order == ["nlA00", "mskA10"]
    assert set(outcomes.values()) == {Outcome(Status.OK)}


def test_failed_exit_rotation_keeps_hubs_on_old_keys(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(verdicts=["rejected"]), "mskA10": ScriptedNode()},
    )

    report = asyncio.run(env.controller.run(options(rotate_exit_keys=True)))

    assert launches(env, "mskA10") == 0
    assert report.outcomes["mskA10"].status is Status.NOT_ATTEMPTED
    assert run_exit_code(report.outcomes) is ExitCode.PARTIAL
    assert env.stored == ["nlA00"]
    assert report.notes


def test_full_deploy_policy_rotates_only_unlimited_laptop_deploys(tmp_path, monkeypatch) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        fakes(),
        manifest_extra={"keys": {"exit_rotation": "full-deploy"}},
    )

    limited = asyncio.run(env.controller.run(options(limit="mskA10", dry_run=True)))
    assert env.topology.keys.rotated == []
    assert limited.plan.notes
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    report = asyncio.run(env.controller.run(options(dry_run=True)))
    assert env.topology.keys.rotated == []
    assert report.plan.notes
    monkeypatch.delenv("GITHUB_ACTIONS")
    asyncio.run(env.controller.run(options(dry_run=True)))
    assert env.topology.keys.rotated == ["nlA00"]


def test_regenerate_failure_message_is_masked(tmp_path) -> None:
    nodes = {
        "nlA00": make_node(
            "nlA00",
            role="exit",
            ipv4="203.0.113.10",
        ),
        "nlA01": make_node(
            "nlA01",
            role="exit",
            ipv4="203.0.113.11",
        ),
        "mskA10": make_node(
            "mskA10",
            role="hub",
            ipv4="203.0.113.20",
        ),
    }
    env = rollout_env(
        tmp_path,
        nodes,
        {
            "nlA00": ScriptedNode(),
            "nlA01": ScriptedNode(),
            "mskA10": ScriptedNode(),
        },
    )
    secret = "rotated-nlA00-key"
    env.topology.keys.fail = {"nlA01": f"hexrift rejected reality_private_key {secret}"}

    with pytest.raises(ExternalToolError) as excinfo:
        asyncio.run(env.controller.run(options(rotate_exit_keys=True)))

    assert env.topology.keys.rotated == ["nlA00"]
    assert secret not in str(excinfo.value)
    assert MASK in str(excinfo.value)


def test_rotation_refuses_when_a_rotated_exit_is_unreachable(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        {"nlA00": ScriptedNode(unreachable=True), "mskA10": ScriptedNode()},
    )

    with pytest.raises(Refused):
        asyncio.run(env.controller.deploy(options(rotate_exit_keys=True)))

    assert env.stored == []
    assert launches(env, "mskA10") == 0


def test_rotation_refuses_when_a_hub_is_settled_not_planned(tmp_path) -> None:
    env = rollout_env(
        tmp_path,
        fleet(),
        fakes(),
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
    env.transport.nodes["mskA10"].commit = unrelated
    env.transport.nodes["nlA00"].commit = ancestor

    with pytest.raises(Refused):
        asyncio.run(env.controller.deploy(options(rotate_exit_keys=True)))

    assert env.stored == []
