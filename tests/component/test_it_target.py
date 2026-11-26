"""Integration harness: ASTRARIUM_IT_* parsing and harness SSH files, no target needed."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import paramiko
import pytest

from tests.support.it_target import ALIAS, MARKER_PATH, ItConfigError, ItTarget, load_target


pytestmark = pytest.mark.component


def _bare_target(tmp_path: Path) -> ItTarget:
    return ItTarget(
        host="203.0.113.10",
        port=22,
        user="astrarium",
        key=tmp_path / "key",
        host_key="AAAA",
        ssh_dir=tmp_path / "ssh",
    )


def _env(tmp_path: Path) -> dict[str, str]:
    key = tmp_path / "id_ed25519"
    subprocess.run(
        [
            "ssh-keygen",
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "",
            "-f",
            str(key),
        ],
        check=True,
    )
    blob = (tmp_path / "id_ed25519.pub").read_text().split()[1]
    return {
        "ASTRARIUM_IT_HOST": "127.0.0.1",
        "ASTRARIUM_IT_PORT": "2222",
        "ASTRARIUM_IT_USER": "astrarium",
        "ASTRARIUM_IT_KEY": str(key),
        "ASTRARIUM_IT_HOST_KEY": f"ssh-ed25519 {blob}",
        "ASTRARIUM_IT_TARGET_ID": "abc123",
    }


def test_no_it_variables_means_no_target(tmp_path: Path) -> None:
    assert load_target({"PATH": "/usr/bin"}, tmp_path / "ssh") is None


def test_incomplete_it_variables_fail_instead_of_skipping(tmp_path: Path) -> None:
    env = _env(tmp_path)
    del env["ASTRARIUM_IT_HOST_KEY"]

    with pytest.raises(ItConfigError):
        load_target(env, tmp_path / "ssh")


def test_empty_target_id_fails_instead_of_matching_empty_marker(tmp_path: Path) -> None:
    env = _env(tmp_path)
    env["ASTRARIUM_IT_TARGET_ID"] = ""

    with pytest.raises(ItConfigError):
        load_target(env, tmp_path / "ssh")


def test_harness_ssh_files_pin_key_port_and_host_key(tmp_path: Path) -> None:
    env = _env(tmp_path)

    target = load_target(env, tmp_path / "ssh")

    assert target is not None
    resolved = subprocess.run(
        [
            "ssh",
            "-G",
            "-F",
            str(target.ssh_config),
            ALIAS,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    options = {
        name.lower(): value for name, value in (line.split(" ", 1) for line in resolved.splitlines() if " " in line)
    }
    assert options["hostname"] == "127.0.0.1"
    assert options["port"] == "2222"
    assert options["identityfile"] == env["ASTRARIUM_IT_KEY"]
    assert options["identityagent"] == "none"
    assert options["stricthostkeychecking"] == "true"
    assert paramiko.HostKeys(str(target.known_hosts)).lookup("[127.0.0.1]:2222") is not None


def _stub_ssh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, rc: int, stdout: str) -> None:
    """PATH ssh answering rc/stdout only when argv names MARKER_PATH: stands in for real target's marker file."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    script = bin_dir / "ssh"
    script.write_text(
        f"#!{sys.executable}\n"
        "import sys\n"
        f"if {MARKER_PATH!r} not in sys.argv[-1]:\n"
        "    sys.exit(1)\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.exit({rc})\n"
    )
    script.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")


def test_check_marker_passes_when_target_holds_matching_id(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_ssh(
        tmp_path,
        monkeypatch,
        rc=0,
        stdout="abc123\n",
    )

    _bare_target(tmp_path).check_marker("abc123")


def test_check_marker_fails_when_target_id_differs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_ssh(
        tmp_path,
        monkeypatch,
        rc=0,
        stdout="other\n",
    )

    with pytest.raises(AssertionError):
        _bare_target(tmp_path).check_marker("abc123")


def test_check_marker_fails_when_marker_file_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_ssh(
        tmp_path,
        monkeypatch,
        rc=1,
        stdout="",
    )

    with pytest.raises(AssertionError):
        _bare_target(tmp_path).check_marker("abc123")
