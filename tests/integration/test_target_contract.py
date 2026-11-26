"""Target contract: Debian family, systemd PID 1, sshd, passwordless sudo, NET_ADMIN, bbr."""

from __future__ import annotations

import pytest

from tests.support.it_target import ItTarget


pytestmark = pytest.mark.integration

CAP_NET_ADMIN = 12
"""Bit of CAP_NET_ADMIN in /proc/<pid>/status capability masks (linux/capability.h)."""


def test_target_runs_debian_family(it_target: ItTarget) -> None:
    release = dict(
        line.split("=", 1) for line in it_target.run("cat /etc/os-release").stdout.splitlines() if "=" in line
    )
    family = {release.get("ID", "").strip('"'), *release.get("ID_LIKE", "").strip('"').split()}

    assert family & {"debian", "ubuntu"}


def test_systemd_runs_as_pid_1(it_target: ItTarget) -> None:
    assert it_target.run("cat /proc/1/comm").stdout.strip() == "systemd"
    assert it_target.run("systemctl is-system-running", check=False).stdout.strip() in {"running", "degraded"}


def test_login_user_has_passwordless_sudo(it_target: ItTarget) -> None:
    assert it_target.sudo("id -u").stdout.strip() == "0"


def test_root_holds_net_admin(it_target: ItTarget) -> None:
    status = it_target.sudo("cat /proc/self/status").stdout
    effective = next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:"))

    assert (int(effective, 16) >> CAP_NET_ADMIN) & 1 == 1


def test_sshd_answers_on_loopback_port_22(it_target: ItTarget) -> None:
    banner = it_target.run("timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/22 && head -c 8 <&3'").stdout

    assert banner == "SSH-2.0-"


def test_kernel_offers_bbr(it_target: ItTarget) -> None:
    available = it_target.run("cat /proc/sys/net/ipv4/tcp_available_congestion_control").stdout.split()

    assert "bbr" in available
