"""Probe script run by POSIX sh against fake binaries."""

import subprocess

import pytest

from astrarium.components.versions.probe import build_probe_script, parse_probe_output, pin_matches
from astrarium.components.versions.registry import Component


pytestmark = pytest.mark.component


def test_probe_script_reports_versions_markers_and_missing_binaries(tmp_path):
    telemt = tmp_path / "telemt"
    telemt.write_text("#!/bin/sh\necho 'telemt 3.5.7'\n", encoding="utf-8")
    telemt.chmod(0o755)
    wgcf = tmp_path / "wgcf"
    wgcf.write_text("", encoding="utf-8")
    marker = tmp_path / "wgcf-marker"
    marker.write_text("2.2.31\n", encoding="utf-8")
    absent = tmp_path / "blocky"
    components = [
        Component(
            "telemt",
            "nullforge",
            None,
            str(telemt),
            f"{telemt} --version",
            "telemt",
            "telemt",
        ),
        Component(
            "wgcf",
            "nullforge",
            None,
            str(wgcf),
            f"cat {marker}",
            "warp",
            "warp:engine_type=wireguard",
        ),
        Component(
            "blocky",
            "nullforge",
            None,
            str(absent),
            f"{absent} version",
            "dns",
            "dns:mode=blocky",
        ),
    ]
    script = build_probe_script(components)
    output = subprocess.run(
        [
            "sh",
            "-c",
            script,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    found = parse_probe_output(output)
    assert (
        pin_matches(
            components[0],
            "3.5.7",
            found["telemt"],
        )
        is True
    )
    assert (
        pin_matches(
            components[1],
            "2.2.31",
            found["wgcf"],
        )
        is True
    )
    assert found["blocky"].present is False
