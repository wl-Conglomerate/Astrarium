"""versions list and outdated: upstream comparison, probe states, lookup failures."""

import asyncio
from dataclasses import replace

import pytest

from astrarium.components.rollout.artifacts import XRAY_REPO
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.versions.controller import ListOptions, latest_versions, outdated_rows
from astrarium.components.versions.probe import NO_HOST_KEYS
from astrarium.components.versions.registry import build_registry, listed_components
from astrarium.repo import Repo
from tests.support.fleet import NO_LOCK, TransportPool, fleet, manifest_from
from tests.support.versions_upstream import FakeTopology, ReleaseSource, make_release, versions_controller


pytestmark = pytest.mark.component

XRAY_RELEASE = {"version": "v26.3.27", "sha256": {"x86_64": "a" * 64}}


def _upstream():
    return ReleaseSource(
        releases={
            "telemt/telemt": [make_release("3.6.0", pre=True), make_release("3.5.7")],
            XRAY_REPO: [make_release("v26.9.9", pre=True), make_release("v26.3.27")],
        },
        heads={XRAY_REPO: "b" * 40},
    )


def _outdated(manifest, *, pre, upstream=None):
    registry = build_registry(manifest, NO_LOCK)
    names = listed_components(
        registry,
        manifest,
        all_components=False,
    )
    latest = latest_versions(
        registry,
        names,
        manifest,
        _upstream() if upstream is None else upstream,
        pre=pre,
    )
    return {
        (row.component, row.where)
        for row in outdated_rows(
            manifest,
            registry,
            names,
            {},
            latest,
        )
    }


def test_outdated_compares_stable_releases_unless_pre():
    manifest = manifest_from(
        fleet(),
        versions={"telemt": "3.5.6", "xray": XRAY_RELEASE},
        node_versions={"plsA00": {"telemt": "3.5.8"}},
    )
    assert _outdated(manifest, pre=False) == {("telemt", "manifest")}
    assert _outdated(manifest, pre=True) == {
        ("telemt", "manifest"),
        ("telemt", "node plsA00"),
        ("xray", "manifest"),
    }


def test_head_pin_is_outdated_until_it_is_upstream_main_head():
    upstream = _upstream()
    manifest = manifest_from(fleet(), versions={"xray": "main@" + "a" * 40})
    assert _outdated(
        manifest,
        pre=False,
        upstream=upstream,
    ) == {("xray", "manifest")}
    upstream.heads[XRAY_REPO] = "a" * 40
    assert (
        _outdated(
            manifest,
            pre=False,
            upstream=upstream,
        )
        == set()
    )


def test_failed_upstream_lookups_are_warnings_not_errors():
    manifest = manifest_from(fleet(), versions={"telemt": "3.5.6"})
    registry = build_registry(manifest, NO_LOCK)
    latest = latest_versions(
        registry,
        ["xray", "telemt"],
        manifest,
        ReleaseSource(),
        pre=False,
    )
    assert latest["telemt"].version is None
    assert latest["telemt"].error is not None


def test_list_probes_as_deploy_user_and_flags_mismatches(tmp_path):
    nodes = fleet()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    pool = TransportPool()
    pool.get("deploy", "jump").replies[("plsA00", "@@astrarium")] = CommandResult(
        rc=0,
        stdout="@@astrarium telemt\ntelemt 3.5.6\n",
        stderr="",
    )
    controller = versions_controller(
        Repo(root=tmp_path),
        upstream=_upstream(),
        topology=FakeTopology(manifest, nodes),
        pool=pool,
    )
    report = asyncio.run(
        controller.list_versions(
            ListOptions(
                node=None,
                all_components=False,
                probe=True,
                via=None,
            )
        )
    )
    telemt = next(row for row in report.rows if row.name == "telemt")
    assert (
        telemt.pin,
        telemt.layer,
        telemt.latest.version,
    ) == (
        "3.5.7",
        "manifest",
        "3.5.7",
    )
    assert telemt.cells["plsA00"].state == "mismatch"
    assert "edge" not in {node_id for node_id, _ in pool.get("deploy", "jump").calls}


def test_list_leaves_nodes_without_host_keys_out_of_the_probe(tmp_path):
    nodes = fleet()
    nodes["plsA00"] = replace(nodes["plsA00"], host_keys={})
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    pool = TransportPool()
    controller = versions_controller(
        Repo(root=tmp_path),
        upstream=_upstream(),
        topology=FakeTopology(manifest, nodes),
        pool=pool,
    )
    report = asyncio.run(
        controller.list_versions(
            ListOptions(
                node=None,
                all_components=False,
                probe=True,
                via=None,
            )
        )
    )
    telemt = next(row for row in report.rows if row.name == "telemt")
    assert telemt.cells["plsA00"].state == NO_HOST_KEYS
    assert "plsA00" not in {node_id for node_id, _ in pool.get("deploy", "jump").calls}
