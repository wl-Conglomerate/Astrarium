"""Fake node for payload tests: fake root, HOME and stub sudo/systemctl/xray/haproxy on PATH."""

from __future__ import annotations

import hashlib
import os
import subprocess
from importlib.resources import files
from pathlib import Path


PAYLOAD = Path(str(files("astrarium.payloads") / "apply.sh"))

COMMIT = "c" * 40

OLD_BUILD = "1a2b3c4"

NEW_BUILD = "d" * 40

SUDO = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG/sudo"
exec "$@"
"""

"""Logs argv exactly as passed to sudo, then runs it (sudo options would make exec fail)."""

SYSTEMCTL = """#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG/systemctl"
eval "last=\\${$#}"
[ -e "$STUB_LOG/$1-$last-fails" ] && exit 1
case "$1" in
    is-active)
        [ -e "$STUB_LOG/$3-down" ] && exit 3
        case "$3" in
            xray) file="$ASTRARIUM_ROOT/usr/local/etc/xray/config.json" ;;
            *) file="$ASTRARIUM_ROOT/etc/haproxy/haproxy.cfg" ;;
        esac
        grep -q UNHEALTHY "$file" 2>/dev/null && exit 3
        exit 0 ;;
    show) cat "$STUB_LOG/active-enter" 2>/dev/null ;;
esac
exit 0
"""

"""Service health follows UNHEALTHY marker in live file or `<service>-down` flag file.
An action (restart/enable/disable/reload) fails when `<verb>-<service>-fails` is flagged."""

HAPROXY = """#!/bin/sh
grep -q INVALID "$3" && exit 1
exit 0
"""


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "-"


def xray_stub(build: str, *, rejects: str | None) -> str:
    """Fake xray: `version` reports build, `run -test` fails on INVALID (and on `rejects` marker)."""

    reject = f'grep -q {rejects} "$4" && exit 23' if rejects else ":"
    return f"""#!/bin/sh
case "$1" in
    version)
        echo "Xray 26.3.27 (Xray, Penetrates Everything.) {build} (go1.25.1 linux/amd64)"
        echo "A unified platform." ;;
    run) grep -q INVALID "$4" && exit 23
         {reject}
         echo "Configuration OK." ;;
    *) exit 1 ;;
esac
"""


def _executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


class FakeNode:
    """Fake root with live xray binary (old build), HOME with run dir and stage, stubs on PATH."""

    @property
    def config(self) -> Path:
        return self.root / "usr/local/etc/xray/config.json"

    @property
    def haproxy_cfg(self) -> Path:
        return self.root / "etc/haproxy/haproxy.cfg"

    @property
    def xray_bin(self) -> Path:
        return self.root / "usr/local/bin/xray"

    def stage_file(self, name: str, text: str) -> None:
        (self.stage / name).write_text(text)

    def stage_xray(self, build: str) -> None:
        _executable(self.stage / "xray", xray_stub(build, rejects=None))

    def fail_service_action(self, verb: str, service: str) -> None:
        (self.logs / f"{verb}-{service}-fails").touch()

    def __init__(self, tmp: Path, run_id: str = "r1") -> None:
        self.root = tmp / "root"
        self.home = tmp / "home"
        self.logs = tmp / "logs"
        self.run_id = run_id
        bin_dir = tmp / "bin"
        for directory in (
            "usr/local/etc/xray",
            "etc/haproxy",
            "usr/local/bin",
            "usr/sbin",
        ):
            (self.root / directory).mkdir(parents=True)
        for directory in (
            self.home,
            self.logs,
            bin_dir,
        ):
            directory.mkdir()
        _executable(bin_dir / "sudo", SUDO)
        _executable(bin_dir / "systemctl", SYSTEMCTL)
        _executable(self.root / "usr/sbin/haproxy", HAPROXY)
        _executable(self.xray_bin, xray_stub(OLD_BUILD, rejects="NEEDS_NEW_XRAY"))
        self.env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "HOME": str(self.home),
            "ASTRARIUM_ROOT": str(self.root),
            "STUB_LOG": str(self.logs),
        }
        self.base = self.home / ".astrarium"
        self.run_dir = self.base / "runs" / run_id
        self.stage = self.run_dir / "stage.T3st0001"
        self.stage.mkdir(parents=True)

    def params(self, **overrides: str) -> dict[str, str]:
        """Payload parameters matching current live and staged files."""

        params = {
            "RUN": self.run_id,
            "STAGE": str(self.stage),
            "COMMIT": COMMIT,
            "EXPECT_COMMIT": "-",
            "SETTLE": "0",
            "LOCK_WAIT": "2",
            "WAIT": "20",
            "CONFIG_BEFORE": sha(self.config),
            "HAPROXY_BEFORE": sha(self.haproxy_cfg),
            "XRAY_BEFORE": sha(self.xray_bin),
            "CONFIG_NEW": sha(self.stage / "config.json"),
            "HAPROXY_NEW": sha(self.stage / "haproxy.cfg"),
            "XRAY_NEW": sha(self.stage / "xray"),
            "HAPROXY_INSTALLED": "0",
            "XRAY_EXPECT": "-",
        }
        params.update(overrides)
        return params

    def invoke(self, mode: str, params: dict[str, str], script: Path = PAYLOAD) -> subprocess.CompletedProcess[str]:
        argv = [
            "bash",
            str(script),
            mode,
            *(f"{key}={value}" for key, value in params.items()),
        ]
        return subprocess.run(
            argv,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def apply(self, **overrides: str) -> str | None:
        """Run apply mode in foreground, return recorded result."""

        self.invoke("apply", self.params(**overrides))
        return self.result()

    def state(self) -> str:
        path = self.run_dir / "state"
        return path.read_text() if path.exists() else ""

    def result(self) -> str | None:
        results = [line.split("=", 1)[1] for line in self.state().splitlines() if line.startswith("result=")]
        return results[-1] if results else None

    def calls(self, tool: str) -> list[str]:
        """Logged argv lines of stub tool, fake root prefix removed."""

        path = self.logs / tool
        lines = path.read_text().splitlines() if path.exists() else []
        return [line.replace(str(self.root), "") for line in lines]

    def service_actions(self) -> list[str]:
        """Systemctl calls that change state, read-only queries (is-active/status/show) excluded."""

        def subcommand(call: str) -> str:
            for token in call.split():
                if not token.startswith("-"):
                    return token
            return ""

        return [
            call
            for call in self.calls("systemctl")
            if subcommand(call)
            not in (
                "is-active",
                "status",
                "show",
            )
        ]
