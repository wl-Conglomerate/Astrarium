"""Probe script under real bash."""

import platform
import subprocess

import pytest

from astrarium.components.rollout.probe import PROBE_COMMAND, parse_probe


pytestmark = pytest.mark.component


def test_probe_script_reports_arch_and_recorded_commit(tmp_path) -> None:
    (tmp_path / ".astrarium").mkdir()
    (tmp_path / ".astrarium" / "state").write_text(f"commit={'c' * 40}\nrun=r1\n")
    env = {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}

    out = subprocess.run(
        ["bash", "-s"],
        input=PROBE_COMMAND,
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    live = parse_probe(out.stdout)

    assert live.arch == platform.machine()
    assert live.recorded_commit == "c" * 40
