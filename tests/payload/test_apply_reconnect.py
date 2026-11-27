"""Payload launch and reconcile: detached apply under inherited lock, classification after lost connections."""

import os
import signal
import subprocess
import time

import pytest

from tests.support.payload_node import PAYLOAD, FakeNode, sha


pytestmark = pytest.mark.payload

OLD = '{"log": {"loglevel": "warning"}}\n'

NEW = '{"log": {"loglevel": "info"}}\n'

NOOP_HAPROXY_CFG = "global\n    daemon\n"


def write_state(node: FakeNode, *lines: str) -> None:
    node.run_dir.mkdir(parents=True, exist_ok=True)
    (node.run_dir / "state").write_text("".join(f"{line}\n" for line in lines))


def reconcile(node: FakeNode, **overrides: str) -> str:
    out = node.invoke("reconcile", node.params(**overrides)).stdout
    return [line for line in out.splitlines() if line.startswith("result=")][-1].split("=", 1)[1]


def hold_lock(node: FakeNode, seconds: int) -> subprocess.Popen:
    node.base.mkdir(parents=True, exist_ok=True)
    holder = subprocess.Popen(
        [
            "flock",
            str(node.base / "lock"),
            "sleep",
            str(seconds),
        ]
    )
    deadline = time.monotonic() + 10
    while (
        subprocess.run(
            [
                "flock",
                "-n",
                str(node.base / "lock"),
                "true",
            ],
            check=False,
        ).returncode
        == 0
    ):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    return holder


def test_launched_payload_survives_its_caller_and_holds_the_lock(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)
    node.stage_file("apply.sh", PAYLOAD.read_text())
    params = node.params(SETTLE="2")
    argv = [
        "bash",
        str(node.stage / "apply.sh"),
        "launch",
        *(f"{k}={v}" for k, v in params.items()),
    ]

    launcher = subprocess.Popen(
        argv,
        env=node.env,
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    launcher.wait(timeout=10)
    try:
        os.killpg(launcher.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

    assert reconcile(node) == "applied"
    assert node.config.read_text() == NEW


def test_launch_reports_locked_while_another_run_holds_the_lock(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)
    holder = hold_lock(node, 10)
    try:
        out = node.invoke("launch", node.params(LOCK_WAIT="1")).stdout
    finally:
        holder.kill()
        holder.wait()

    assert "result=locked" in out
    assert reconcile(node) == "locked"
    assert node.config.read_text() == OLD


def test_payload_dead_before_swap_is_pending(node: FakeNode) -> None:
    write_state(
        node,
        f"launched={int(time.time()) - 100}",
        "pid=1",
        "step=locked",
        "step=checked",
    )

    assert reconcile(node) == "pending"


def test_reconcile_waits_for_the_lock_holder(node: FakeNode) -> None:
    write_state(node, f"launched={int(time.time())}")
    holder = hold_lock(node, 2)
    started = time.monotonic()
    try:
        result = reconcile(node)
    finally:
        holder.wait()

    assert result == "pending"
    assert time.monotonic() - started >= 1.0


@pytest.mark.parametrize(
    ("active_since", "restarted"),
    [("Mon 2020-01-06 00:00:00 UTC", True), ("Fri 2100-01-01 00:00:00 UTC", False)],
)
def test_interrupted_swap_is_finished(node: FakeNode, active_since: str, restarted: bool) -> None:
    node.config.write_text(NEW)
    (node.logs / "active-enter").write_text(f"{active_since}\n")
    write_state(
        node,
        f"launched={int(time.time()) - 100}",
        "step=locked",
        "step=swapping",
    )

    assert reconcile(node, CONFIG_NEW=sha(node.config)) == "applied"
    assert ("restart xray" in node.service_actions()) is restarted
    assert "result=applied" in node.state()
    assert "commit=" in (node.base / "state").read_text()


def test_mixed_files_after_interrupted_swap_are_unknown(node: FakeNode) -> None:
    node.config.write_text(OLD)
    write_state(
        node,
        f"launched={int(time.time()) - 100}",
        "step=locked",
        "step=swapping",
    )

    assert reconcile(node, CONFIG_NEW="0" * 64) == "unknown"


def test_restart_failure_during_repair_is_unknown_not_applied(node: FakeNode) -> None:
    """Failed restart mid-repair must not read as healthy just because old process is still up."""

    node.config.write_text(NEW)
    node.haproxy_cfg.write_text(NOOP_HAPROXY_CFG)
    (node.logs / "active-enter").write_text("Mon 2020-01-06 00:00:00 UTC\n")
    write_state(
        node,
        f"launched={int(time.time()) - 100}",
        "step=locked",
        "step=swapping",
    )
    node.fail_service_action("disable", "haproxy")

    result = reconcile(
        node,
        HAPROXY_INSTALLED="1",
        CONFIG_NEW=sha(node.config),
        HAPROXY_NEW=sha(node.haproxy_cfg),
    )

    assert result == "unknown"
    actions = node.service_actions()
    assert "disable --now haproxy" in actions
    assert "restart xray" not in actions
    assert not (node.base / "state").exists()
