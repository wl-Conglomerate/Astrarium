"""Private per-run directory for decrypted material, generated SSH files and builds."""

from __future__ import annotations

import os
import shutil
import signal
import stat
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any


RUNTIME_PREFIX = "astrarium-run-"

OWNER_FILE = "owner.pid"

FALLBACK_TMP = Path("/tmp")  # noqa: S108

SignalHandler = Callable[[int, FrameType | None], Any] | int | signal.Handlers | None

TERMINATING_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
"""Signals turned into SystemExit while runtime dir is open (SIGINT raises KeyboardInterrupt already).

Signal inherited as ignored (nohup) stays ignored.
"""


def _base_dir() -> Path:
    base = Path(tempfile.gettempdir())
    if any(ch.isspace() for ch in str(base)) and FALLBACK_TMP.is_dir():
        return FALLBACK_TMP
    return base


def _terminate(signum: int, _frame: FrameType | None) -> None:
    raise SystemExit(128 + signum)


def _reclaim_and_retry(func: Callable[..., Any], path: str, _exc: BaseException) -> None:
    """onexc hook for shutil.rmtree: grant u+w+x on failing entry and its parent, retry once."""

    for target in {path, os.path.dirname(path) or path}:
        try:
            os.chmod(target, os.stat(target).st_mode | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
    try:
        func(path)
    except OSError:
        pass


def write_private_file(path: Path, text: str) -> None:
    """Write text to path 0600, replacing any existing content."""

    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    with os.fdopen(
        descriptor,
        "w",
        encoding="utf-8",
    ) as handle:
        handle.write(text)
    path.chmod(0o600)


class RuntimeDir:
    """Private per-run dir under system temp, 0700, removed on exit and on SIGINT/SIGTERM/SIGHUP."""

    path: Path

    def __init__(self) -> None:
        self._previous: dict[signal.Signals, SignalHandler] = {}

    def __enter__(self) -> RuntimeDir:
        self.path = Path(tempfile.mkdtemp(prefix=RUNTIME_PREFIX, dir=_base_dir()))
        self.path.chmod(0o700)
        (self.path / OWNER_FILE).write_text(f"{os.getpid()}\n")
        if threading.current_thread() is threading.main_thread():
            for signum in TERMINATING_SIGNALS:
                previous = signal.getsignal(signum)
                if previous == signal.SIG_IGN:
                    continue
                self._previous[signum] = previous
                signal.signal(signum, _terminate)
        return self

    def __exit__(self, *exc: object) -> None:
        for signum, previous in self._previous.items():
            signal.signal(signum, signal.SIG_DFL if previous is None else previous)
        self._previous.clear()
        shutil.rmtree(self.path, onexc=_reclaim_and_retry)
        if self.path.exists():
            raise RuntimeError(f"could not remove runtime dir {self.path}, private material may remain on disk")

    def sub(self, name: str) -> Path:
        """0700 subdirectory `name`, created once."""

        if Path(name).name != name or name in {
            "",
            ".",
            "..",
        }:
            raise ValueError(f"invalid runtime subdir name {name!r}")
        target = self.path / name
        target.mkdir(mode=0o700, exist_ok=True)
        return target

    @staticmethod
    def leftovers() -> list[Path]:
        """Runtime dirs of this user whose owning process is gone."""

        found: list[Path] = []
        for candidate in sorted(_base_dir().glob(f"{RUNTIME_PREFIX}*")):
            if not candidate.is_dir() or candidate.stat().st_uid != os.getuid():
                continue
            if not _owner_alive(candidate / OWNER_FILE):
                found.append(candidate)
        return found


def _owner_alive(owner_file: Path) -> bool:
    try:
        pid = int(owner_file.read_text().strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True
