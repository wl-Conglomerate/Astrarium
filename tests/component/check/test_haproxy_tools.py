"""Local haproxy version probe: other major.minor yields to container or is flagged."""

from __future__ import annotations

from pathlib import Path

import pytest

from astrarium.components.check.runners import DEFAULT_HAPROXY_IMAGE, haproxy_tools


pytestmark = pytest.mark.component

FAKE_HAPROXY = """#!/bin/sh
[ "$1" = "-v" ] || exit 2
echo "HAProxy version 2.8.5-1 2024/01/01 - https://haproxy.org/"
"""


def test_local_haproxy_on_other_major_minor_yields_to_container_else_is_flagged(tmp_path: Path) -> None:
    haproxy = tmp_path / "haproxy"
    haproxy.write_text(FAKE_HAPROXY)
    haproxy.chmod(0o755)
    local = {"haproxy": str(haproxy)}

    with_engine = haproxy_tools(
        None,
        DEFAULT_HAPROXY_IMAGE,
        {**local, "podman": "/usr/bin/podman"}.get,
    )
    alone = haproxy_tools(
        None,
        DEFAULT_HAPROXY_IMAGE,
        local.get,
    )

    same, same_differs = with_engine.checker("2.8")
    other, other_differs = with_engine.checker("3.2")
    lone, lone_differs = alone.checker("3.2")
    assert same is not None and not same.container and not same_differs
    assert other is not None and other.container and not other_differs
    assert lone is not None and not lone.container and lone_differs
