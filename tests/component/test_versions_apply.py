"""versions apply: casts of NullForge pins, gating, re-probe, --changed-since."""

import asyncio

import pytest
import yaml

from astrarium.components.inventory.cast import CastResult
from astrarium.components.rollout import transport as rollout_transport
from astrarium.components.rollout.outcomes import Status
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.versions.controller import ApplyOptions, plan_apply
from astrarium.components.versions.registry import build_registry
from astrarium.errors import Refused, UsageProblem
from astrarium.repo import Repo
from tests.support.deployment import git
from tests.support.fleet import (
    NO_LOCK,
    ROLE_FEATURES,
    FakeRunner,
    TransportPool,
    fleet,
    make_node,
    manifest_from,
)
from tests.support.versions_upstream import FakeTopology, versions_controller


pytestmark = pytest.mark.component


def _options(*, component="telemt", changed_since=None, identity="admin"):
    return ApplyOptions(
        component=component,
        changed_since=changed_since,
        limit=None,
        canary=None,
        canary_wait=0.0,
        stagger=0.0,
        identity=identity,
        via=None,
        dry_run=False,
        allow_dirty=False,
    )


def _approve(previews):
    return True


def _changed():
    return FakeRunner(script=lambda limits, runes: CastResult(0, [], {node_id: ["Install"] for node_id in limits}, 1))


def _probe(version):
    return CommandResult(
        rc=0,
        stdout=f"@@astrarium telemt\ntelemt {version}\n",
        stderr="",
    )


def _pulsars():
    nodes = fleet()
    nodes["plsA01"] = make_node(
        "plsA01",
        "pulsar",
        ipv4="203.0.113.41",
    )
    return nodes


def _commit(root, manifest):
    text = yaml.safe_dump(manifest.model_dump(mode="json"), sort_keys=False)
    (root / "astrarium.yaml").write_text(text, encoding="utf-8")
    git(
        root,
        "add",
        "-A",
    )
    git(
        root,
        "commit",
        "-q",
        "-m",
        "pins",
    )
    return git(
        root,
        "rev-parse",
        "HEAD",
    )


def test_apply_casts_the_component_rune_only_where_its_feature_is_enabled(tmp_path):
    nodes = fleet()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    registry = build_registry(manifest, NO_LOCK)
    plan = plan_apply(
        nodes,
        manifest,
        registry,
        Repo(root=tmp_path),
        components=["telemt"],
        limit=None,
        identity="admin",
    )
    assert plan.targets == ["plsA00"]
    assert plan.stages == [{"plsA00": ("telemt",)}]
    assert {
        "nlA00",
        "mskA10",
        "edge",
    } <= set(plan.skipped)


@pytest.mark.parametrize("component", ["xray", "nosuch"])
def test_components_without_a_cast_path_are_refused(tmp_path, component):
    nodes = fleet()
    manifest = manifest_from(nodes)
    registry = build_registry(manifest, NO_LOCK)
    with pytest.raises(UsageProblem):
        plan_apply(
            nodes,
            manifest,
            registry,
            Repo(root=tmp_path),
            components=[component],
            limit=None,
            identity="admin",
        )


def test_apply_reprobes_and_fails_nodes_left_on_the_old_version(tmp_path, monkeypatch):
    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: [],
    )
    nodes = _pulsars()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    pool = TransportPool()
    pool.get("admin", "jump").replies[("plsA00", "@@astrarium")] = _probe("3.5.7")
    pool.get("admin", "jump").replies[("plsA01", "@@astrarium")] = _probe("3.5.6")
    runner = FakeRunner(
        script=lambda limits, runes: CastResult(0, [], {node_id: ["telemt | Install telemt"] for node_id in limits}, 1)
    )
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(manifest, nodes),
        pool=pool,
        runner=runner,
    )
    reports = asyncio.run(controller.apply(_options(), _approve))
    assert reports is not None
    assert reports["plsA00"].outcome.status is Status.OK
    assert reports["plsA01"].outcome.status is Status.FAILED
    assert {tuple(runes) for _, runes, _ in runner.calls} == {("telemt",)}


def test_apply_writes_the_cast_identity_ssh_scope_only_once(tmp_path, monkeypatch):
    """pin_verifier's transport must be run_casts's own, not second, independently-scoped
    write of same ssh-<identity>-<via>."""

    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: [],
    )
    nodes = _pulsars()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    pool = TransportPool()
    pool.get("admin", "jump").replies[("plsA00", "@@astrarium")] = _probe("3.5.7")
    pool.get("admin", "jump").replies[("plsA01", "@@astrarium")] = _probe("3.5.6")
    runner = FakeRunner(
        script=lambda limits, runes: CastResult(0, [], {node_id: ["telemt | Install telemt"] for node_id in limits}, 1)
    )
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(manifest, nodes),
        pool=pool,
        runner=runner,
    )
    writes: list[tuple[str, str]] = []
    real_write = rollout_transport.write_ssh_files

    def counting(runtime, scoped_nodes, control, identity, via):
        writes.append((identity, via))
        return real_write(
            runtime,
            scoped_nodes,
            control,
            identity,
            via,
        )

    monkeypatch.setattr(
        rollout_transport,
        "write_ssh_files",
        counting,
    )
    reports = asyncio.run(controller.apply(_options(), _approve))
    assert reports is not None
    assert writes.count(("admin", "jump")) == 1


def test_apply_reports_the_rc_when_the_reprobe_command_itself_fails(tmp_path, monkeypatch):
    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: [],
    )
    nodes = fleet()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    pool = TransportPool()
    pool.get("admin", "jump").replies[("plsA00", "@@astrarium")] = CommandResult(
        rc=7,
        stdout="",
        stderr="boom",
    )
    runner = FakeRunner(
        script=lambda limits, runes: CastResult(0, [], {node_id: ["telemt | Install telemt"] for node_id in limits}, 1)
    )
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(manifest, nodes),
        pool=pool,
        runner=runner,
    )
    reports = asyncio.run(controller.apply(_options(), _approve))
    assert reports is not None
    assert reports["plsA00"].outcome.status is Status.FAILED
    assert "7" in (reports["plsA00"].outcome.reason or "")


def test_apply_refuses_a_dirty_tree(tmp_path, monkeypatch):
    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: ["astrarium.yaml"],
    )
    with pytest.raises(Refused):
        asyncio.run(versions_controller(Repo(root=tmp_path)).apply(_options(), _approve))


def test_changed_since_casts_only_nodes_whose_nullforge_pin_changed(tmp_path):
    nodes = _pulsars()
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from(nodes, versions={"telemt": "3.5.6"}))
    head = manifest_from(
        nodes,
        versions={"telemt": "3.5.6", "xray": "main@" + "a" * 40},
        node_versions={"plsA01": {"telemt": "3.5.7"}},
    )
    _commit(tmp_path, head)
    pool = TransportPool()
    pool.get("ci", "jump").replies[("plsA01", "@@astrarium")] = _probe("3.5.7")
    runner = FakeRunner()
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(head, nodes),
        pool=pool,
        runner=runner,
    )
    reports = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            _approve,
        )
    )
    assert runner.calls == [
        (
            ["plsA01"],
            ["telemt"],
            False,
        )
    ]
    assert reports is not None
    assert reports["plsA01"].outcome.status is Status.UNCHANGED
    assert "plsA00" not in reports


def test_changed_since_leaves_a_ci_bastion_whose_pin_changed_not_attempted(tmp_path):
    nodes = fleet()
    nodes["edge"] = make_node(
        "edge",
        "bastion",
        ipv4="198.51.100.20",
        ssh_port=22443,
        ssh_user="operator",
        admin_user=None,
        sections={**ROLE_FEATURES["bastion"], "telemt": ROLE_FEATURES["pulsar"]["telemt"]},
    )
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from(nodes, versions={"telemt": "3.5.6"}))
    head = manifest_from(nodes, versions={"telemt": "3.5.7"})
    _commit(tmp_path, head)
    pool = TransportPool()
    pool.get("ci", "jump").replies[("plsA00", "@@astrarium")] = _probe("3.5.7")
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(head, nodes),
        pool=pool,
        runner=_changed(),
    )

    pushed = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            _approve,
        )
    )
    named = asyncio.run(controller.apply(_options(identity="ci"), _approve))

    assert pushed is not None and named is not None
    assert pushed["edge"].outcome.status is Status.NOT_ATTEMPTED
    assert named["edge"].outcome.status is Status.SKIPPED


def test_changed_since_never_casts_a_broad_rune(tmp_path):
    nodes = fleet()
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from(nodes))
    head = manifest_from(nodes, versions={"curl": "8.99.0"})
    _commit(tmp_path, head)
    runner = FakeRunner()
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(head, nodes),
        runner=runner,
    )

    reports = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            _approve,
        )
    )

    assert runner.calls == []
    assert reports is not None
    assert {node_id: report.outcome.status for node_id, report in reports.items()} == dict.fromkeys(
        nodes, Status.NOT_ATTEMPTED
    )


def test_component_without_probe_is_reported_unverified(tmp_path, monkeypatch):
    monkeypatch.setattr(
        Repo,
        "dirty_paths",
        lambda self: [],
    )
    nodes = fleet()
    custom = {
        "owner": "nullforge",
        "upstream": "example/tool",
        "binary": "/usr/local/bin/tool",
        "rune": "telemt",
    }
    manifest = manifest_from(
        nodes,
        versions={"tool": "1.0.0"},
        components={"tool": {**custom, "feature": "telemt"}},
    )
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(manifest, nodes),
        pool=TransportPool(),
        runner=_changed(),
    )

    reports = asyncio.run(controller.apply(_options(component="tool"), _approve))

    assert reports is not None
    assert reports["plsA00"].outcome.status is Status.OK
    assert reports["plsA00"].outcome.reason


def test_changed_since_reports_nodes_new_since_base_as_skipped(tmp_path):
    nodes = _pulsars()
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from({key: node for key, node in nodes.items() if key != "plsA01"}))
    head = manifest_from(nodes)
    _commit(tmp_path, head)
    controller = versions_controller(Repo(root=tmp_path), topology=FakeTopology(head, nodes))

    reports = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            _approve,
        )
    )

    assert reports is not None
    assert reports["plsA01"].outcome.status is Status.SKIPPED


def test_changed_since_without_nullforge_pin_change_neither_decrypts_nor_asks(tmp_path, monkeypatch):
    nodes = fleet()
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from(nodes, versions={"xray": "main@" + "a" * 40}))
    head = manifest_from(nodes, versions={"xray": "main@" + "b" * 40})
    _commit(tmp_path, head)
    topology = FakeTopology(head, nodes)
    prepared: list[bool] = []
    asked: list[object] = []
    real_prepare = topology.prepare

    def prepare(runtime, *, need_keys):
        prepared.append(need_keys)
        return real_prepare(runtime, need_keys=need_keys)

    def confirm(previews):
        asked.append(previews)
        return True

    monkeypatch.setattr(
        topology,
        "prepare",
        prepare,
    )
    controller = versions_controller(Repo(root=tmp_path), topology=topology)

    reports = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            confirm,
        )
    )

    assert reports == {}
    assert prepared == []
    assert asked == []


def test_changed_since_declined_confirmation_casts_nothing(tmp_path):
    nodes = fleet()
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    base = _commit(tmp_path, manifest_from(nodes, versions={"telemt": "3.5.6"}))
    head = manifest_from(nodes, versions={"telemt": "3.5.7"})
    _commit(tmp_path, head)
    runner = FakeRunner()
    controller = versions_controller(
        Repo(root=tmp_path),
        topology=FakeTopology(head, nodes),
        runner=runner,
    )

    reports = asyncio.run(
        controller.apply(
            _options(
                component=None,
                changed_since=base,
                identity="ci",
            ),
            lambda previews: False,
        )
    )

    assert reports is None
    assert runner.calls == []
