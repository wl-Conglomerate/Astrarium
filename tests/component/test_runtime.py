"""Private runtime dir lifecycle."""

import os
import shutil
import signal
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from astrarium import runtime as runtime_module
from astrarium.runtime import RUNTIME_PREFIX, RuntimeDir


pytestmark = pytest.mark.component


def test_runtime_dir_is_private_and_removed_on_error():
    with pytest.raises(RuntimeError), RuntimeDir() as runtime:
        keys = runtime.sub("keys")
        (keys / "nlA00.yaml").write_text("secret\n")
        assert runtime.path.stat().st_mode & 0o777 == 0o700
        assert keys.stat().st_mode & 0o777 == 0o700
        assert not any(ch.isspace() for ch in str(runtime.path))
        raise RuntimeError("boom")
    assert not runtime.path.exists()


@pytest.mark.skipif(os.getuid() == 0, reason="permission checks are bypassed for root")
def test_readonly_subdir_left_by_a_tool_is_still_removed():
    """Tool leaving read-only subdir behind must not survive cleanup with secrets in it."""

    with RuntimeDir() as runtime:
        keys = runtime.sub("keys")
        (keys / "left-behind.yaml").write_text("secret\n")
        keys.chmod(0o500)
    assert not runtime.path.exists()


def test_exit_raises_when_cleanup_leaves_the_dir_behind(monkeypatch: pytest.MonkeyPatch):
    """Cleanup failure must surface, not vanish behind ignore_errors."""

    runtime = RuntimeDir()
    runtime.__enter__()
    monkeypatch.setattr(
        runtime_module.shutil,
        "rmtree",
        lambda *_a, **_k: None,
    )
    with pytest.raises(RuntimeError) as excinfo:
        runtime.__exit__(
            None,
            None,
            None,
        )
    assert str(runtime.path) in str(excinfo.value)
    monkeypatch.undo()
    shutil.rmtree(runtime.path, ignore_errors=True)


@pytest.mark.parametrize(
    "signum",
    [signal.SIGTERM, signal.SIGHUP],
    ids=lambda signum: signum.name,
)
def test_termination_signal_removes_runtime_dir(tmp_path: Path, signum: signal.Signals):
    script = textwrap.dedent(
        """
        import sys, time
        from astrarium.runtime import RuntimeDir
        with RuntimeDir() as runtime:
            (runtime.sub("keys") / "k.yaml").write_text("secret")
            print(runtime.path, flush=True)
            time.sleep(30)
        """
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            script,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )  # noqa: S603
    assert proc.stdout is not None
    path = Path(proc.stdout.readline().strip())
    assert path.is_dir()
    proc.send_signal(signum)
    proc.wait(timeout=10)
    assert proc.returncode != 0
    assert not path.exists()


def test_leftovers_lists_dirs_of_dead_processes_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        runtime_module.tempfile,
        "gettempdir",
        lambda: str(tmp_path),
    )
    stale = tmp_path / f"{RUNTIME_PREFIX}stale"
    stale.mkdir()
    (stale / "owner.pid").write_text("999999999\n")
    with RuntimeDir() as live:
        assert live.path.parent == tmp_path
        assert RuntimeDir.leftovers() == [stale]
    assert os.path.isdir(stale)
