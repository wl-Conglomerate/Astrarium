"""Provision planning: targets, bastion guard, stages, Orrery conflict, dirty tree, dry run."""

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from astrarium.app import AstrariumApp
from astrarium.components.inventory.controller import InventoryController, ProvisionOptions, plan_provision
from astrarium.components.manifest.models import CiControl
from astrarium.components.rollout.outcomes import Status
from astrarium.errors import InvalidManifest, Refused
from astrarium.repo import Repo
from tests.support.deployment import fixture_app, make_deployment
from tests.support.fleet import FakeRunner, fleet, make_control, make_node


pytestmark = pytest.mark.component


def _label(argument):
    return Path(argument).stem if argument.endswith(".py") else argument


def test_bastions_are_cast_only_when_named_by_id(tmp_path):
    repo, nodes, control = (
        Repo(root=tmp_path),
        fleet(),
        make_control(),
    )
    assert (
        "edge"
        in plan_provision(
            nodes,
            control,
            repo,
            limit=None,
            runes=[],
            identity="admin",
        ).skipped
    )
    by_role = plan_provision(
        nodes,
        control,
        repo,
        limit="@bastion,nlA00",
        runes=[],
        identity="admin",
    )
    assert "edge" in by_role.skipped
    assert by_role.targets == ["nlA00"]
    assert plan_provision(
        nodes,
        control,
        repo,
        limit="edge",
        runes=[],
        identity="admin",
    ).targets == ["edge"]


def test_full_provision_casts_nullforge_then_access_repo_and_role_runes(tmp_path):
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / "orrery.py").write_text('"""Orrery."""\n', encoding="utf-8")
    nodes = fleet()
    nodes["plsA00"] = replace(nodes["plsA00"], runes=["tor"])
    plan = plan_provision(
        nodes,
        make_control(),
        Repo(root=tmp_path),
        limit="nlA00,plsA00",
        runes=[],
        identity="admin",
    )
    full, extras = plan.stages
    assert full == {"nlA00": (), "plsA00": ()}
    assert [_label(argument) for argument in extras["nlA00"]] == [
        "deploy_access",
        "ci_access",
        "orrery",
    ]
    assert [_label(argument) for argument in extras["plsA00"]] == [
        "deploy_access",
        "ci_access",
        "orrery",
        "tor",
    ]


def test_full_provision_applies_revoked_ci_cast_keys(tmp_path):
    control = make_control().model_copy(update={"ci": CiControl(cast_user="astrarium_ci", cast_keys=[])})
    plan = plan_provision(
        fleet(),
        control,
        Repo(root=tmp_path),
        limit="nlA00",
        runes=[],
        identity="admin",
    )
    assert "ci_access" in [_label(argument) for argument in plan.stages[-1]["nlA00"]]


def test_explicit_runes_replace_the_full_provision(tmp_path):
    plan = plan_provision(
        fleet(),
        make_control(),
        Repo(root=tmp_path),
        limit="plsA00",
        runes=["telemt"],
        identity="admin",
    )
    assert plan.stages == [{"plsA00": ("telemt",)}]


def test_jump_only_access_on_orrery_collector_is_refused(tmp_path):
    with pytest.raises(Refused):
        plan_provision(
            fleet(),
            make_control(orrery_host="edge"),
            Repo(root=tmp_path),
            limit="edge",
            runes=[],
            identity="admin",
        )


def test_reserved_group_name_target_is_refused_while_planning(tmp_path):
    nodes = fleet()
    nodes["hub"] = make_node(
        "hub",
        "hub",
        ipv4="203.0.113.31",
    )
    with pytest.raises(InvalidManifest):
        plan_provision(
            nodes,
            make_control(),
            Repo(root=tmp_path),
            limit="hub",
            runes=[],
            identity="admin",
        )


def test_access_errors_are_raised_while_planning(tmp_path):
    """CI cast keys without control.jump fail in plan_provision, before ssh files and confirmation."""

    with pytest.raises(InvalidManifest):
        plan_provision(
            fleet(),
            make_control(jump=None),
            Repo(root=tmp_path),
            limit="nlA00",
            runes=[],
            identity="admin",
        )


def test_ci_identity_never_casts_bastions(tmp_path):
    plan = plan_provision(
        fleet(),
        make_control(),
        Repo(root=tmp_path),
        limit="edge,nlA00",
        runes=[],
        identity="ci",
    )
    assert plan.targets == ["nlA00"]
    assert "edge" in plan.skipped


def test_provision_refuses_dirty_tree(tmp_path, monkeypatch):
    (tmp_path / "astrarium.yaml").write_text("deployment: {name: test}\nnodes: {}\n", encoding="utf-8")
    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: ["astrarium.yaml"],
    )
    options = ProvisionOptions(
        limit=None,
        runes=[],
        dry_run=False,
        identity="admin",
        via=None,
        canary=None,
        canary_wait=0.0,
        stagger=0.0,
        allow_dirty=False,
    )
    with pytest.raises(Refused):
        asyncio.run(AstrariumApp(tmp_path).inventory.provision(options, lambda previews: True))


def test_provision_dry_run_on_fixture_deployment(tmp_path, monkeypatch):
    """Real TopologyController/HexRift build, fake cast runner: dry run casts nothing for real."""

    root = make_deployment(tmp_path / "repo")
    app = fixture_app(root)
    runner = FakeRunner()
    monkeypatch.setattr(
        InventoryController,
        "make_runner",
        lambda self: runner,
    )
    options = ProvisionOptions(
        limit=None,
        runes=[],
        dry_run=True,
        identity="admin",
        via=None,
        canary=None,
        canary_wait=0.0,
        stagger=0.0,
        allow_dirty=False,
    )

    reports = asyncio.run(app.inventory.provision(options, lambda previews: True))

    assert reports is not None
    assert reports["edge"].outcome.status is Status.SKIPPED  # bastion, not named in --limit
    cast_nodes = {node_id: report for node_id, report in reports.items() if node_id != "edge"}
    assert cast_nodes  # at least one non-bastion fixture node was actually cast
    assert all(report.outcome.status is Status.UNCHANGED for report in cast_nodes.values())
    assert runner.calls
    assert all(dry for *_rest, dry in runner.calls)
