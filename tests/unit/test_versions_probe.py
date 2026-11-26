"""Pin matching and per-node version cells."""

import asyncio
import logging

import pytest

from astrarium.components.manifest.models import Arch, XrayRelease
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.secrets.masking import MASK, ValueMasker
from astrarium.components.versions.probe import PROBE_MARK, InstalledVersion, node_cells, pin_matches, probe_nodes
from astrarium.components.versions.registry import XRAY, Component, build_registry
from tests.support.fleet import NO_LOCK, ScriptedTransport, fleet, manifest_from


pytestmark = pytest.mark.unit

SHA = "a" * 40


def _telemt():
    return build_registry(manifest_from(fleet()), NO_LOCK)["telemt"]


def _wgcf():
    return build_registry(manifest_from(fleet()), NO_LOCK)["wgcf"]


def _probe_component(name: str) -> Component:
    return Component(
        name=name,
        owner="nullforge",
        upstream=None,
        binary=None,
        probe="true",
        rune=None,
        feature=None,
    )


@pytest.mark.parametrize(
    (
        "pin",
        "line",
        "matches",
    ),
    [
        (
            "3.5.7",
            "telemt 3.5.7",
            True,
        ),
        (
            "v3.5.7",
            "telemt 3.5.7 (built 2026-01-01)",
            True,
        ),
        (
            "v0.12.4",
            "NVIM v0.12.4",
            True,
        ),
        (
            "3.5.8",
            "telemt 3.5.7",
            False,
        ),
        (
            "3.5.1",
            "telemt 3.5.10",
            False,
        ),
        (
            "3.6",
            "tmux 3.6a",
            False,
        ),
        (
            "latest",
            "telemt 1.0.0",
            True,
        ),
    ],
)
def test_nullforge_pins_match_whole_version_tokens(pin, line, matches):
    assert (
        pin_matches(
            _telemt(),
            pin,
            InstalledVersion(
                "telemt",
                True,
                (line,),
            ),
        )
        is matches
    )


def test_missing_binary_never_matches():
    assert (
        pin_matches(
            _telemt(),
            "3.5.7",
            InstalledVersion(
                "telemt",
                False,
                (),
            ),
        )
        is False
    )


def test_marker_tracked_component_uses_exact_equality_not_substring():
    """wgcf has no version command, NullForge compares marker line to pin exactly (no v-strip)."""

    installed = InstalledVersion(
        "wgcf",
        True,
        ("2.2.31",),
    )
    assert (
        pin_matches(
            _wgcf(),
            "2.2.3",
            installed,
        )
        is False
    )
    assert (
        pin_matches(
            _wgcf(),
            "2.2.31",
            installed,
        )
        is True
    )


def test_xray_matches_release_by_version_field_and_head_by_build_commit():
    installed = InstalledVersion(
        "xray",
        True,
        (f"Xray 26.3.27 (Xray, Penetrates Everything.) {SHA} (go1.25 linux/amd64)",),
    )
    digests: dict[Arch, str] = {"x86_64": "0" * 64}
    assert (
        pin_matches(
            XRAY,
            XrayRelease(version="v26.3.27", sha256=digests),
            installed,
        )
        is True
    )
    assert (
        pin_matches(
            XRAY,
            XrayRelease(version="v26.9.9", sha256=digests),
            installed,
        )
        is False
    )
    assert (
        pin_matches(
            XRAY,
            f"main@{SHA}",
            installed,
        )
        is True
    )
    assert (
        pin_matches(
            XRAY,
            "main@" + "b" * 40,
            installed,
        )
        is False
    )


def test_cells_cover_enabled_components_and_flag_mismatch():
    nodes = fleet()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    registry = build_registry(manifest, NO_LOCK)
    probes = {
        "telemt": InstalledVersion(
            "telemt",
            True,
            ("telemt 3.5.6",),
        )
    }
    cells = {
        cell.component: cell
        for cell in node_cells(
            nodes["plsA00"],
            manifest,
            registry,
            ["telemt", "xray"],
            probes,
            probed=True,
        )
    }
    assert set(cells) == {"telemt"}
    assert (cells["telemt"].state, cells["telemt"].layer) == ("mismatch", "manifest")
    [bastion] = node_cells(
        nodes["edge"],
        manifest,
        registry,
        ["blocky"],
        None,
        probed=False,
    )
    assert bastion.state == "not probed"


def test_probe_nodes_parses_output_and_fails_closed_on_nonzero_rc():
    transport = ScriptedTransport(
        replies={
            ("nlA00", ""): CommandResult(
                rc=0,
                stdout=f"{PROBE_MARK}telemt\ntelemt 3.5.7\n",
                stderr="",
            ),
            ("nlA01", ""): CommandResult(
                rc=1,
                stdout="",
                stderr="boom",
            ),
        }
    )
    components = {"nlA00": [_probe_component("telemt")], "nlA01": [_probe_component("telemt")]}

    result, failed = asyncio.run(
        probe_nodes(
            transport,
            ["nlA00", "nlA01"],
            components,
            ValueMasker(),
        )
    )

    assert result["nlA00"] == {
        "telemt": InstalledVersion(
            "telemt",
            True,
            ("telemt 3.5.7",),
        )
    }
    assert result["nlA01"] is None
    assert failed == {"nlA01": 1}


def test_probe_nodes_logs_rc_and_masks_dropped_stderr(caplog):
    transport = ScriptedTransport(
        replies={
            ("nlA00", ""): CommandResult(
                rc=1,
                stdout="",
                stderr="token deadbeef1234 rejected",
            )
        }
    )
    masker = ValueMasker()
    masker.add("deadbeef1234")

    with caplog.at_level(logging.WARNING):
        result, failed = asyncio.run(
            probe_nodes(
                transport,
                ["nlA00"],
                {"nlA00": [_probe_component("telemt")]},
                masker,
            )
        )

    assert result["nlA00"] is None
    assert failed == {"nlA00": 1}
    assert "deadbeef1234" not in caplog.text
    assert MASK in caplog.text
    assert "nlA00" in caplog.text


def test_probe_output_is_masked_before_truncation():
    secret = "s3cr3t-value-0123456789abcdef"
    line = "x" * 190 + secret
    transport = ScriptedTransport(
        replies={
            ("nlA00", ""): CommandResult(
                rc=0,
                stdout=f"{PROBE_MARK}telemt\n{line}\n",
                stderr="",
            )
        }
    )
    masker = ValueMasker()
    masker.add(secret)

    result, _ = asyncio.run(
        probe_nodes(
            transport,
            ["nlA00"],
            {"nlA00": [_probe_component("telemt")]},
            masker,
        )
    )

    found = result["nlA00"]
    assert found is not None
    shown = " ".join(found["telemt"].lines)
    assert secret[:8] not in shown
