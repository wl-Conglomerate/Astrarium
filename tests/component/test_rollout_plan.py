"""Per-node plans: prerequisites, what changes, binary comparison, masked diffs."""

import hashlib
import json
from pathlib import Path

import pytest

from astrarium.components.manifest.models import XrayRelease
from astrarium.components.rollout.artifacts import XrayArtifact
from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.plan import NodePlan, artifact_required, plan_node
from astrarium.components.rollout.probe import LiveState
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.topology.bridge import BuiltNode
from tests.support.nodes import make_node


pytestmark = pytest.mark.component

HEAD_SHA = "a" * 40

KNOWN_VALUE = "reality-private-key-value"

NOOP_CFG = "global\n    daemon\n"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def plan(node, built, state, artifact=None, force=False, text=None) -> NodePlan | Outcome:
    return plan_node(
        node,
        built,
        state,
        artifact,
        force=force,
        masker=ValueMasker(),
        live_config_text=text,
    )


def built_in(tmp_path: Path, config: str, haproxy: str = NOOP_CFG, wanted: bool = False) -> BuiltNode:
    (tmp_path / "config.json").write_text(config)
    (tmp_path / "haproxy.cfg").write_text(haproxy)
    return BuiltNode(
        "nlA00",
        tmp_path / "config.json",
        tmp_path / "haproxy.cfg",
        wanted,
    )


def live(config: str | None, **kw) -> LiveState:
    defaults = dict(
        config_sha=sha(config) if config is not None else None,
        haproxy_sha=None,
        xray_sha="9" * 64,
        xray_build=HEAD_SHA,
        recorded_commit=None,
        arch="x86_64",
    )
    defaults.update(kw)
    return LiveState(**defaults)


def test_missing_xray_binary_is_prerequisite(tmp_path) -> None:
    result = plan(
        make_node("nlA00"),
        built_in(tmp_path, "{}"),
        live("{}", xray_sha=None),
    )

    assert result == Outcome(Status.FAILED, "prerequisite")


def test_wanted_haproxy_without_feature_fails(tmp_path) -> None:
    built = built_in(
        tmp_path,
        "{}",
        "frontend fe\n",
        wanted=True,
    )

    result = plan(
        make_node("nlA00"),
        built,
        live("{}"),
    )

    assert isinstance(result, Outcome)
    assert result.status is Status.FAILED


def test_installed_and_wanted_haproxy_is_planned(tmp_path) -> None:
    node = make_node("nlA00", features={"haproxy": {"install": True}, "xray": {"install": True}})
    built = built_in(
        tmp_path,
        "{}",
        "frontend fe\n",
        wanted=True,
    )

    result = plan(
        node,
        built,
        live("{}", haproxy_sha=None),
    )

    assert isinstance(result, NodePlan)
    assert result.haproxy == built.haproxy_cfg
    assert result.haproxy_installed
    assert result.haproxy_wanted


def test_absent_haproxy_file_is_ignored_when_feature_is_off(tmp_path) -> None:
    result = plan(
        make_node("nlA00"),
        built_in(tmp_path, "{}"),
        live("{}", haproxy_sha=None),
    )

    assert result == Outcome(Status.UNCHANGED)


def test_missing_live_config_counts_as_change(tmp_path) -> None:
    result = plan(
        make_node("nlA00"),
        built_in(tmp_path, "{}"),
        live(None),
    )

    assert isinstance(result, NodePlan)
    assert result.config is not None


def test_force_plans_identical_node(tmp_path) -> None:
    result = plan(
        make_node("nlA00"),
        built_in(tmp_path, "{}"),
        live("{}"),
        force=True,
    )

    assert isinstance(result, NodePlan)


def test_head_pin_compares_build_not_bytes(tmp_path) -> None:
    node = make_node("nlA00", versions={"xray": f"main@{HEAD_SHA}"})
    rebuilt = XrayArtifact(
        "x86_64",
        tmp_path / "xray",
        "8" * 64,
        f"main@{HEAD_SHA}",
    )

    assert plan(
        node,
        built_in(tmp_path, "{}"),
        live("{}"),
        rebuilt,
    ) == Outcome(Status.UNCHANGED)
    moved = live("{}", xray_build="b" * 40)
    assert isinstance(
        plan(
            node,
            built_in(tmp_path, "{}"),
            moved,
            rebuilt,
        ),
        NodePlan,
    )


def test_release_pin_compares_binary_hash(tmp_path) -> None:
    node = make_node("nlA00", versions={"xray": XrayRelease(version="v26.3.27", sha256={"x86_64": "0" * 64})})
    same = XrayArtifact(
        "x86_64",
        tmp_path / "xray",
        "9" * 64,
        "v26.3.27",
    )
    other = XrayArtifact(
        "x86_64",
        tmp_path / "xray",
        "7" * 64,
        "v26.3.27",
    )

    assert plan(
        node,
        built_in(tmp_path, "{}"),
        live("{}"),
        same,
    ) == Outcome(Status.UNCHANGED)
    assert isinstance(
        plan(
            node,
            built_in(tmp_path, "{}"),
            live("{}"),
            other,
        ),
        NodePlan,
    )


def test_arch_mismatch_fails(tmp_path) -> None:
    result = plan(
        make_node("nlA00", arch="aarch64"),
        built_in(tmp_path, "{}"),
        live("{}"),
    )

    assert isinstance(result, Outcome)
    assert result.status is Status.FAILED


def test_diff_masks_both_sides(tmp_path) -> None:
    old = json.dumps(
        {
            "inbounds": [
                {
                    "privateKey": "old-private-key",
                    "tag": "a",
                    "note": KNOWN_VALUE,
                }
            ]
        }
    )
    new = json.dumps(
        {
            "inbounds": [
                {
                    "privateKey": "new-private-key",
                    "tag": "b",
                    "note": KNOWN_VALUE,
                }
            ]
        }
    )
    masker = ValueMasker()
    masker.add(KNOWN_VALUE)

    result = plan_node(
        make_node("nlA00"),
        built_in(tmp_path, new),
        live(old),
        None,
        force=False,
        masker=masker,
        live_config_text=old,
    )

    assert isinstance(result, NodePlan)
    assert '"tag": "b"' in result.diff
    for leaked in (
        "old-private-key",
        "new-private-key",
        KNOWN_VALUE,
    ):
        assert leaked not in result.diff


def test_invalid_live_json_hides_diff_content(tmp_path) -> None:
    unregistered = "unregistered-secret-value"
    old = f'{{"note": "{unregistered}",'

    result = plan(
        make_node("nlA00"),
        built_in(tmp_path, "{}"),
        live(old),
        text=old,
    )

    assert isinstance(result, NodePlan)
    assert unregistered not in result.diff


def test_head_artifact_needed_when_build_differs_or_given() -> None:
    pin = f"main@{HEAD_SHA}"

    assert (
        artifact_required(
            pin,
            live("{}"),
            "x86_64",
            (),
        )
        is False
    )
    assert (
        artifact_required(
            pin,
            live("{}", xray_build="b" * 40),
            "x86_64",
            (),
        )
        is True
    )
    assert (
        artifact_required(
            pin,
            live("{}"),
            "x86_64",
            ("x86_64",),
        )
        is True
    )
    assert (
        artifact_required(
            None,
            live("{}"),
            "x86_64",
            (),
        )
        is False
    )
