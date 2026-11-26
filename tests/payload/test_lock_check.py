"""Deploy lock check command against real flock (util-linux)."""

import os
import signal
import subprocess
import time

import pytest

from astrarium.components.inventory.paths import LOCK_BUSY_RC, lock_check_command


pytestmark = pytest.mark.payload


def _check(env):
    return subprocess.run(
        [
            "sh",
            "-c",
            lock_check_command("github_actions"),
        ],
        env=env,
        check=False,
    ).returncode


def _env(tmp_path, home):
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "sudo").write_text('#!/bin/sh\n[ "$1" = "-n" ] && shift\nexec "$@"\n', encoding="utf-8")
    (stubs / "getent").write_text(f'#!/bin/sh\necho "github_actions:x:999:999::{home}:/bin/bash"\n', encoding="utf-8")
    for stub in stubs.iterdir():
        stub.chmod(0o755)
    return {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}"}


def test_lock_check_reports_busy_only_while_deploy_holds_the_lock(tmp_path):
    home = tmp_path / "home"
    (home / ".astrarium").mkdir(parents=True)
    lock = home / ".astrarium" / "lock"
    env = _env(tmp_path, home)
    assert _check(env) == 0
    lock.touch()
    # own session: flock forks sleep as child, killing only flock pid would leave that child
    # holding lock (fork duplicates locked fd) until its own sleep ran out
    holder = subprocess.Popen(
        [
            "flock",
            str(lock),
            "sleep",
            "30",
        ],
        start_new_session=True,
    )
    try:
        deadline = time.monotonic() + 10
        while (
            subprocess.run(
                [
                    "flock",
                    "-n",
                    str(lock),
                    "true",
                ],
                check=False,
            ).returncode
            == 0
        ):
            assert time.monotonic() < deadline
            time.sleep(0.05)
        assert _check(env) == LOCK_BUSY_RC
    finally:
        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait()
    assert _check(env) == 0
