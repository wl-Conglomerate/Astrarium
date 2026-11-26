"""Disposable integration target from ASTRARIUM_IT_* environment: harness SSH files, commands, ssh-agent.

Mock environment only: nothing run here is production evidence. Never point it at fleet node.
Session fixture confirms MARKER_PATH on target before first test (check_marker), so stray env pointing at
real host fails closed instead of running commands there.
"""

from __future__ import annotations

import ipaddress
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from collections.abc import Generator, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from astrarium.components.manifest.models import ARCH_BY_MACHINE, Arch


ENV_PREFIX = "ASTRARIUM_IT_"

TARGET_ID_ENV = "ASTRARIUM_IT_TARGET_ID"

REQUIRED_ENV = (
    "ASTRARIUM_IT_HOST",
    "ASTRARIUM_IT_USER",
    "ASTRARIUM_IT_KEY",
    "ASTRARIUM_IT_HOST_KEY",
    TARGET_ID_ENV,
)
"""ASTRARIUM_IT_PORT is optional (default 22)."""

ALIAS = "it-target"

COMMAND_TIMEOUT = 120.0

MARKER_PATH = "/etc/astrarium-it-target"
"""Opt-in marker: VM or spare host writes this file by hand, content equal to TARGET_ID_ENV, to be usable
as integration target. Container target writes it at build time with random id."""

AGENT_START_TIMEOUT = 10.0


class ItConfigError(ValueError):
    """ASTRARIUM_IT_* variables set but incomplete or malformed."""


@dataclass(frozen=True)
class SshHost:
    """One Host block of harness ssh_config."""

    alias: str
    hostname: str
    user: str
    port: int = 22
    proxy_jump: str | None = None


def harness_ssh_config(key: Path, known_hosts: Path, hosts: Iterable[SshHost]) -> str:
    """ssh_config read by OpenSSH and paramiko: strict host keys, only `key`, no agent."""

    lines = [
        "Host *",
        "    StrictHostKeyChecking yes",
        f"    UserKnownHostsFile {known_hosts}",
        "    GlobalKnownHostsFile /dev/null",
        "    BatchMode yes",
        "    IdentitiesOnly yes",
        f"    IdentityFile {key}",
        "    IdentityAgent none",
        "    ConnectTimeout 15",
        "    LogLevel ERROR",
    ]
    for host in hosts:
        lines += [
            "",
            f"Host {host.alias}",
            f"    HostName {host.hostname}",
            f"    User {host.user}",
        ]
        if host.port != 22:
            # pyinfra mis-compares explicit Port 22 on ProxyJump hops
            lines.append(f"    Port {host.port}")
        if host.proxy_jump is not None:
            lines.append(f"    ProxyJump {host.proxy_jump}")
    return "\n".join(lines) + "\n"


@dataclass(frozen=True)
class ItTarget:
    """Target contract: Debian family, systemd PID 1, sshd on port 22 inside, passwordless sudo, NET_ADMIN."""

    host: str

    port: int

    user: str

    key: Path

    host_key: str

    ssh_dir: Path

    @property
    def ssh_config(self) -> Path:
        return self.ssh_dir / "ssh_config"

    @property
    def known_hosts(self) -> Path:
        return self.ssh_dir / "known_hosts"

    def endpoint(self) -> str:
        return self.host if self.port == 22 else f"[{self.host}]:{self.port}"

    def sudo(
        self,
        script: str,
        *,
        check: bool = True,
        timeout: float = COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            f"sudo -n sh -c {shlex.quote(script)}",
            check=check,
            timeout=timeout,
        )

    def client_address(self) -> str:
        return self.run('printf "%s" "${SSH_CONNECTION%% *}"').stdout

    def public_key(self) -> str:
        """`ssh-ed25519 <base64>` of harness key, comment dropped."""

        out = subprocess.run(
            [
                "ssh-keygen",
                "-y",
                "-f",
                str(self.key),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        return " ".join(out.stdout.split()[:2])

    def run(
        self,
        command: str,
        *,
        check: bool = True,
        stdin: str | None = None,
        timeout: float = COMMAND_TIMEOUT,
    ) -> subprocess.CompletedProcess[str]:
        """Run `command` as login user, AssertionError on non-zero exit when `check`."""

        proc = subprocess.run(
            [
                "ssh",
                "-F",
                str(self.ssh_config),
                ALIAS,
                command,
            ],
            input="" if stdin is None else stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if check and proc.returncode != 0:
            raise AssertionError(f"target command {command!r} exited {proc.returncode}: {proc.stderr.strip()}")
        return proc

    def write_root_file(self, path: str, content: str, *, owner: str, mode: str) -> None:
        """Create or replace file as root, then set `owner` (user:group) and `mode`."""

        script = 'umask 077 && cat > "$1" && chown "$2" "$1" && chmod "$3" "$1"'
        args = " ".join(
            shlex.quote(value)
            for value in (
                path,
                owner,
                mode,
            )
        )
        self.run(f"sudo -n sh -c {shlex.quote(script)} sh {args}", stdin=content)

    def arch(self) -> Arch:
        """Manifest arch of target from `uname -m`."""

        machine = self.run("uname -m").stdout.strip()
        if machine not in ARCH_BY_MACHINE:
            raise AssertionError(f"unsupported target machine {machine!r}")
        return ARCH_BY_MACHINE[machine]

    def check_marker(self, target_id: str) -> None:
        """Confirm MARKER_PATH on target reads target_id exactly, AssertionError otherwise (opt in by hand)."""

        actual = self.run(f"cat {MARKER_PATH}").stdout.strip()
        if actual != target_id:
            raise AssertionError(
                f"target marker at {MARKER_PATH} reads {actual!r}, expected {TARGET_ID_ENV} {target_id!r}"
            )


def load_target(env: Mapping[str, str], ssh_dir: Path) -> ItTarget | None:
    """Target from ASTRARIUM_IT_* variables plus harness SSH files, None when no such variable is set."""

    if not any(name.startswith(ENV_PREFIX) for name in env):
        return None
    missing = [name for name in REQUIRED_ENV if not env.get(name, "")]
    if missing:
        raise ItConfigError(f"integration target variables missing: {', '.join(missing)} (see it-target.sh)")
    host = env["ASTRARIUM_IT_HOST"]
    try:
        ipaddress.IPv4Address(host)
    except ValueError as e:
        raise ItConfigError(f"ASTRARIUM_IT_HOST must be an IPv4 address (it becomes a manifest ipv4): {host!r}") from e
    port = env.get("ASTRARIUM_IT_PORT", "22")
    if not port.isdigit():
        raise ItConfigError(f"ASTRARIUM_IT_PORT must be a port number: {port!r}")
    key = Path(env["ASTRARIUM_IT_KEY"]).expanduser()
    if not key.is_file():
        raise ItConfigError(f"ASTRARIUM_IT_KEY {key} is not a file")
    host_key = env["ASTRARIUM_IT_HOST_KEY"].split()
    if len(host_key) < 2 or host_key[0] != "ssh-ed25519":
        raise ItConfigError("ASTRARIUM_IT_HOST_KEY must read `ssh-ed25519 <base64>`")
    target = ItTarget(
        host=host,
        port=int(port),
        user=env["ASTRARIUM_IT_USER"],
        key=key,
        host_key=host_key[1],
        ssh_dir=ssh_dir,
    )
    ssh_dir.mkdir(parents=True, exist_ok=True)
    target.known_hosts.write_text(f"{target.endpoint()} ssh-ed25519 {target.host_key}\n")
    target.ssh_config.write_text(
        harness_ssh_config(
            key,
            target.known_hosts,
            [
                SshHost(
                    ALIAS,
                    host,
                    target.user,
                    port=target.port,
                )
            ],
        )
    )
    return target


@contextmanager
def ssh_agent(key: Path) -> Generator[dict[str, str]]:
    """Private ssh-agent holding only `key`, yields environment overlay with SSH_AUTH_SOCK."""
    # short dir under /tmp: unix socket paths stop near 104 bytes on macOS
    folder = Path(tempfile.mkdtemp(prefix="ait-", dir="/tmp"))
    sock = folder / "agent.sock"
    agent = subprocess.Popen(
        [
            "ssh-agent",
            "-D",
            "-a",
            str(sock),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + AGENT_START_TIMEOUT
        while not sock.exists():
            if agent.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("ssh-agent did not start")
            time.sleep(0.05)
        overlay = {"SSH_AUTH_SOCK": str(sock)}
        subprocess.run(
            [
                "ssh-add",
                "-q",
                str(key),
            ],
            env={**os.environ, **overlay},
            capture_output=True,
            check=True,
        )
        yield overlay
    finally:
        agent.terminate()
        agent.wait(timeout=10)
        shutil.rmtree(folder, ignore_errors=True)
