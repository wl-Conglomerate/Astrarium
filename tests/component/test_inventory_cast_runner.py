"""CastRunner subprocess plumbing, with fake interpreter and with pinned NullForge."""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from astrarium.components.inventory.cast import CastResult, CastRunner, parse_cast_output
from tests.support.fake_cast import documents, fake_python, recorded_calls, results_doc


pytestmark = pytest.mark.component


def _inventory(tmp_path):
    folder = tmp_path / "inventory"
    folder.mkdir()
    path = folder / "astrarium_inventory.py"
    path.write_text("exit = [('nlA00', {'ssh_hostname': '203.0.113.1'})]\n", encoding="utf-8")
    return path


def test_run_parses_stdout_streams_stderr_and_runs_in_inventory_dir(tmp_path):
    inventory = _inventory(tmp_path)
    python, record = fake_python(
        tmp_path,
        stdout=documents(results_doc({"telemt | Install telemt": ["plsA00"]})),
        stderr_lines=["--> Loading inventory..."],
    )
    lines: list[str] = []
    result = CastRunner(python=str(python)).run_streaming(
        inventory,
        ["plsA00"],
        ["telemt"],
        dry=False,
        on_stderr=lines.append,
    )
    assert result == CastResult(
        rc=0,
        failed_hosts=[],
        changed={"plsA00": ["telemt | Install telemt"]},
        stages=1,
    )
    assert lines == ["--> Loading inventory..."]
    [call] = recorded_calls(record)
    assert Path(call["cwd"]).resolve() == inventory.parent.resolve()


def test_cast_subprocess_inherits_only_allowlisted_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("SOPS_AGE_KEY", "AGE-SECRET-KEY-1FAKE")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_fake")
    monkeypatch.setenv("UV_INDEX_PHOTON_PASSWORD", "fake-password")
    monkeypatch.setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")
    monkeypatch.setenv("LC_MESSAGES", "C")
    python, record = fake_python(tmp_path, stdout="")

    CastRunner(python=str(python)).run(
        _inventory(tmp_path),
        ["nlA00"],
        [],
        dry=False,
    )

    [call] = recorded_calls(record)
    env = call["env"]
    assert not {"SOPS_AGE_KEY", "UV_INDEX_PHOTON_PASSWORD"} & set(env)
    assert env["GITHUB_TOKEN"] == "ghs_fake"
    assert env["SSH_AUTH_SOCK"] == "/tmp/agent.sock"
    assert env["LC_MESSAGES"] == "C"
    assert env["PATH"] == os.environ["PATH"]


def test_nonzero_exit_without_json_is_returned_not_raised(tmp_path):
    python, _ = fake_python(
        tmp_path,
        stdout="",
        rc=1,
    )
    result = CastRunner(python=str(python)).run(
        _inventory(tmp_path),
        ["nlA00"],
        [],
        dry=False,
    )
    assert (
        result.rc,
        result.failed_hosts,
        result.stages,
    ) == (
        1,
        [],
        0,
    )


def test_pinned_nullforge_accepts_argv_and_prints_parseable_json(tmp_path):
    inventory = _inventory(tmp_path)
    argv = CastRunner().argv(
        inventory,
        ["nlA00"],
        ["users"],
        dry=True,
    )
    # limit matching no host: pyinfra contacts nothing (pyinfra_cli/cli.py:762-780)
    argv[argv.index("nlA00")] = "nomatch"
    result = subprocess.run(
        argv,
        cwd=inventory.parent,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert result.returncode == 0
    assert parse_cast_output(result.stdout) == (
        [],
        {},
        1,
    )


def _fake_nullforge(tmp_path: Path) -> tuple[Path, Path]:
    """Stand-in for `python -m nullforge.cli`: spawns its own child (stand-in for pyinfra) via
    subprocess.run, exactly like NullForge's own cast runner, so real
    kill-child-on-exception behaviour of subprocess.run's except-all clause is exercised for real.
    """

    pidfile = tmp_path / "grandchild.pid"
    child_src = (
        "import os\n"
        f"with open({str(pidfile)!r}, 'w', encoding='utf-8') as handle:\n"
        "    handle.write(str(os.getpid()))\n"
        "import time\n"
        "time.sleep(30)\n"
    )
    script = tmp_path / "fake-nullforge"
    script.write_text(
        f"#!{sys.executable}\n"
        "import pathlib, subprocess, sys, time\n"
        f"child = subprocess.Popen([{sys.executable!r}, '-c', {child_src!r}])\n"
        f"pidfile = pathlib.Path({str(pidfile)!r})\n"
        "deadline = time.monotonic() + 10\n"
        "while not pidfile.exists() and time.monotonic() < deadline:\n"
        "    time.sleep(0.02)\n"
        "print('--> starting pyinfra', file=sys.stderr)\n"
        "sys.stderr.flush()\n"
        "try:\n"
        "    child.communicate(timeout=120)\n"
        "except BaseException:\n"
        "    child.kill()\n"
        "    raise\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script, pidfile


def test_error_path_lets_nullforge_kill_its_own_pyinfra_child(tmp_path):
    """on_stderr raising must not orphan pyinfra grandchild (cast.py's error path sends
    SIGINT, not SIGKILL, so NullForge's own subprocess.run kills its pyinfra child itself)."""

    inventory = _inventory(tmp_path)
    script, pidfile = _fake_nullforge(tmp_path)

    def _boom(_line: str) -> None:
        raise RuntimeError("astrarium-side failure while streaming stderr")

    with pytest.raises(RuntimeError):
        CastRunner(python=str(script)).run_streaming(
            inventory,
            ["nlA00"],
            [],
            dry=False,
            on_stderr=_boom,
        )

    grandchild_pid = int(pidfile.read_text(encoding="utf-8"))
    deadline = time.monotonic() + 5
    alive = True
    while time.monotonic() < deadline:
        try:
            os.kill(grandchild_pid, 0)
        except ProcessLookupError:
            alive = False
            break
        time.sleep(0.05)
    if alive:
        os.kill(grandchild_pid, 9)  # cleanup: don't leave it running past this test
    assert not alive, "pyinfra grandchild survived astrarium's error path"
