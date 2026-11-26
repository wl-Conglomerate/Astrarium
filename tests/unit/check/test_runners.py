"""HAProxy checker selection and test stand-in decisions."""

from __future__ import annotations

from pathlib import Path

import pytest

from astrarium.components.check.runners import DEFAULT_HAPROXY_IMAGE, HaproxyChecker, haproxy_step, pick_haproxy


pytestmark = pytest.mark.unit

ENGINES = {"podman": "/usr/bin/podman", "docker": "/usr/bin/docker"}


def _first(checker: HaproxyChecker | None) -> str | None:
    return None if checker is None else checker.prefix[0]


def test_pick_haproxy_prefers_explicit_then_local_then_podman_then_docker() -> None:
    everything = {"haproxy": "/usr/sbin/haproxy", **ENGINES}

    assert (
        _first(
            pick_haproxy(
                Path("/opt/haproxy"),
                DEFAULT_HAPROXY_IMAGE,
                everything.get,
            )
        )
        == "/opt/haproxy"
    )
    assert (
        _first(
            pick_haproxy(
                None,
                DEFAULT_HAPROXY_IMAGE,
                everything.get,
            )
        )
        == "/usr/sbin/haproxy"
    )
    assert (
        _first(
            pick_haproxy(
                None,
                DEFAULT_HAPROXY_IMAGE,
                ENGINES.get,
            )
        )
        == "/usr/bin/podman"
    )
    assert (
        _first(
            pick_haproxy(
                None,
                DEFAULT_HAPROXY_IMAGE,
                {"docker": "/usr/bin/docker"}.get,
            )
        )
        == "/usr/bin/docker"
    )
    assert (
        pick_haproxy(
            None,
            DEFAULT_HAPROXY_IMAGE,
            {}.get,
        )
        is None
    )


def test_container_check_mounts_workdir_as_root_with_node_version() -> None:
    checker = pick_haproxy(
        None,
        DEFAULT_HAPROXY_IMAGE,
        ENGINES.get,
    )
    assert checker is not None
    digest = "registry.example.net/haproxy@sha256:" + "0" * 64
    pinned = pick_haproxy(
        None,
        digest,
        ENGINES.get,
    )
    assert pinned is not None

    workdir = Path("/work")
    argv = checker.argv(
        workdir / "haproxy.cfg",
        workdir,
        "3.2",
    )

    assert argv[:2] == ["/usr/bin/podman", "run"]
    assert "docker.io/library/haproxy:3.2" in argv
    assert f"{workdir}:{workdir}:ro" in argv
    assert argv[argv.index("--user") + 1] == "0"
    assert argv[-3:] == [
        "-c",
        "-f",
        str(workdir / "haproxy.cfg"),
    ]
    assert digest in pinned.argv(
        workdir / "haproxy.cfg",
        workdir,
        "3.2",
    )


def test_haproxy_step_follows_install_and_wanted() -> None:
    assert haproxy_step(installed=False, wanted=False) == "skip"
    assert haproxy_step(installed=False, wanted=True) == "fail"
    assert haproxy_step(installed=True, wanted=False) == "run"
