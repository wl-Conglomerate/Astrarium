"""Jump-only and CI cast key lines on disposable target, as Astrarium writes them (mock evidence)."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from astrarium.components.inventory.access import ci_line, jump_only_line
from astrarium.components.inventory.cast import CastRunner
from astrarium.components.inventory.render import INVENTORY_FILENAME
from astrarium.runes._policy import HOP_SSHD_DROPIN_PATH, ci_sudoers_body, hop_sshd_dropin
from tests.support.it_target import ItTarget, SshHost, harness_ssh_config


pytestmark = pytest.mark.integration

HOP_USER = "astrarium_hop"

CAST_USER = "astrarium_cast"

LOOPBACK = "127.0.0.1"

FLEET_ENDPOINT = f"{LOOPBACK}:22"

"""Only endpoint hop account may open: target's own sshd, standing in for fleet node behind jump."""

OTHER_ENDPOINT = "127.0.0.2:22"

"""Same sshd through another loopback address: reachable, never permitted."""

PROBE_FILE = "/root/astrarium-it-cast"

SSH_TIMEOUT = 60.0

CAST_RUNE = f'''\
"""Integration rune: root shell and upload as root through CI cast key."""

import io

from pyinfra.operations import files, server

server.shell(
    name="astrarium it: root shell",
    commands=['test "$(id -u)" = 0'],
    _sudo=True,
)

files.put(
    name="astrarium it: upload as root",
    src=io.StringIO("cast-ok\\n"),
    dest="{PROBE_FILE}",
    mode="0600",
    _sudo=True,
)
'''


def _ssh(config: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "ssh",
            "-F",
            str(config),
            *args,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=SSH_TIMEOUT,
        check=False,
    )


@dataclass(frozen=True)
class HopFiles:
    """ssh_config and known_hosts routing through jump-only hop account."""

    config: Path
    known_hosts: Path


def _account(target: ItTarget, user: str, key_line: str) -> None:
    target.sudo(
        f"id -u {user} >/dev/null 2>&1 || useradd --system --user-group --create-home --home-dir /home/{user} "
        f"--shell /bin/bash {user}; install -d -m 700 -o {user} -g {user} /home/{user}/.ssh"
    )
    target.write_root_file(
        f"/home/{user}/.ssh/authorized_keys",
        key_line + "\n",
        owner=f"{user}:{user}",
        mode="0600",
    )


@pytest.fixture(scope="module")
def hop(it_target: ItTarget, tmp_path_factory: pytest.TempPathFactory) -> Iterator[HopFiles]:
    """Hop and CI cast accounts carrying Astrarium key lines, hop sshd drop-in active, harness files routing
    through hop.
    """

    key = it_target.public_key()
    sudoers = f"/etc/sudoers.d/{CAST_USER}"
    try:
        _account(
            it_target,
            HOP_USER,
            jump_only_line(key, [FLEET_ENDPOINT]),
        )
        _account(
            it_target,
            CAST_USER,
            ci_line(key, [LOOPBACK]),
        )
        it_target.write_root_file(
            sudoers,
            ci_sudoers_body(CAST_USER),
            owner="root:root",
            mode="0440",
        )
        it_target.sudo(f"visudo -cf {sudoers}")
        it_target.write_root_file(
            HOP_SSHD_DROPIN_PATH,
            hop_sshd_dropin([HOP_USER]),
            owner="root:root",
            mode="0644",
        )
        it_target.sudo("sshd -t")
        it_target.sudo("systemctl reload ssh")
        effective = it_target.sudo(f"sshd -T -C user={HOP_USER},host=it,addr={LOOPBACK}").stdout.splitlines()
        for directive in (
            "allowtcpforwarding local",
            "allowstreamlocalforwarding no",
            "permittty no",
        ):
            assert directive in effective, effective
        folder = tmp_path_factory.mktemp("hop")
        known_hosts = folder / "known_hosts"
        known_hosts.write_text(
            f"{it_target.endpoint()} ssh-ed25519 {it_target.host_key}\n{LOOPBACK} ssh-ed25519 {it_target.host_key}\n"
        )
        config = folder / "ssh_config"
        hosts = [
            SshHost(
                "hop",
                it_target.host,
                HOP_USER,
                port=it_target.port,
            ),
            SshHost(
                "inner",
                LOOPBACK,
                it_target.user,
                proxy_jump="hop",
            ),
            SshHost(
                "itcast",
                LOOPBACK,
                CAST_USER,
                proxy_jump="hop",
            ),
            SshHost(
                "cast-direct",
                it_target.host,
                CAST_USER,
                port=it_target.port,
            ),
        ]
        config.write_text(
            harness_ssh_config(
                it_target.key,
                known_hosts,
                hosts,
            )
        )
        yield HopFiles(config=config, known_hosts=known_hosts)
    finally:
        it_target.sudo(
            f"rm -f {sudoers} {PROBE_FILE} {HOP_SSHD_DROPIN_PATH}; userdel -r {HOP_USER}; userdel -r {CAST_USER}",
            check=False,
        )
        it_target.sudo("systemctl reload ssh", check=False)


def test_jump_only_key_carries_proxyjump_to_fleet_endpoint(hop: HopFiles, it_target: ItTarget) -> None:
    proc = _ssh(
        hop.config,
        "inner",
        "id -un",
    )

    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == it_target.user


def test_jump_only_key_opens_nothing_else(hop: HopFiles) -> None:
    permitted = _ssh(
        hop.config,
        "-W",
        FLEET_ENDPOINT,
        "hop",
    )
    other = _ssh(
        hop.config,
        "-W",
        OTHER_ENDPOINT,
        "hop",
    )
    shell = _ssh(
        hop.config,
        "hop",
        "echo astrarium-shell",
    )

    assert permitted.stdout.startswith("SSH-2.0-"), permitted.stderr
    assert other.returncode != 0
    assert "SSH-2.0-" not in other.stdout
    assert shell.returncode != 0
    assert "astrarium-shell" not in shell.stdout


def test_jump_only_key_forwarded_listener_is_refused(hop: HopFiles) -> None:
    """Hop sshd drop-in refuses -R: allowed forward would run forced command and exit 1, not 255."""

    proc = _ssh(
        hop.config,
        "-o",
        "ExitOnForwardFailure=yes",
        "-R",
        "127.0.0.1:0:127.0.0.1:22",
        "hop",
        "true",
    )

    assert proc.returncode == 255, proc.stderr


def test_ci_cast_key_runs_pyinfra_cast_through_jump_host(hop: HopFiles, it_target: ItTarget, tmp_path: Path) -> None:
    inventory = tmp_path / "inventory" / INVENTORY_FILENAME
    inventory.parent.mkdir()
    host_data = {
        "ssh_config_file": str(hop.config),
        "ssh_known_hosts_file": str(hop.known_hosts),
        "ssh_strict_host_key_checking": "yes",
        "ssh_user": CAST_USER,
    }
    inventory.write_text(f"it = [('itcast', {host_data!r})]\n")
    rune = tmp_path / "it_cast_probe.py"
    rune.write_text(CAST_RUNE)
    log: list[str] = []

    result = CastRunner().run_streaming(
        inventory,
        ["itcast"],
        [str(rune)],
        dry=False,
        on_stderr=log.append,
    )

    assert (result.rc, result.failed_hosts) == (0, []), "\n".join(log[-40:])
    assert it_target.sudo(f"cat {PROBE_FILE}").stdout == "cast-ok\n"


def test_ci_cast_key_is_refused_away_from_jump_host(hop: HopFiles, it_target: ItTarget) -> None:
    if it_target.client_address() in {LOOPBACK, "::1"}:
        pytest.skip("runner reaches target from loopback, from= restriction not observable here")

    proc = _ssh(
        hop.config,
        "cast-direct",
        "true",
    )

    assert proc.returncode == 255
