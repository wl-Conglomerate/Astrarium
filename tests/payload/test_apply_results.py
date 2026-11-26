"""Payload apply mode against fake root: every apply result, HAProxy table, sudo argv, backups."""

import os
import signal
import stat
import subprocess
import time

import pytest

from tests.support.payload_node import COMMIT, NEW_BUILD, FakeNode


pytestmark = pytest.mark.payload

OLD = '{"log": {"loglevel": "warning"}}\n'

NEW = '{"log": {"loglevel": "info"}}\n'

NOOP_CFG = "global\n    daemon\n"

FRONTED_CFG = "global\n    daemon\nfrontend fe\n    bind :443\n"

OLD_FRONTED_CFG = "global\n    daemon\nfrontend fe\n    bind :443\n    mode http\n"

ALLOWED_EXACT = {
    "systemctl restart xray",
    "systemctl enable --now haproxy",
    "systemctl disable --now haproxy",
    "systemctl reload haproxy",
}


def hold_lock(node: FakeNode, seconds: int) -> subprocess.Popen[bytes]:
    """Start lock holder in its own process group, wait until it actually holds lock."""

    node.base.mkdir(parents=True, exist_ok=True)
    lock = str(node.base / "lock")
    holder = subprocess.Popen(
        [
            "flock",
            lock,
            "sleep",
            str(seconds),
        ],
        start_new_session=True,
    )
    deadline = time.monotonic() + 10
    while (
        subprocess.run(
            [
                "flock",
                "-n",
                lock,
                "true",
            ],
            check=False,
        ).returncode
        == 0
    ):
        assert time.monotonic() < deadline
        time.sleep(0.05)
    return holder


def test_applied_swaps_backs_up_and_records_node_state(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)

    assert node.apply() == "applied"
    assert node.config.read_text() == NEW
    assert stat.S_IMODE(node.config.stat().st_mode) == 0o644
    assert (node.base / "backup" / "r1" / "config.json").read_text() == OLD
    assert f"commit={COMMIT}" in (node.base / "state").read_text()
    assert not node.stage.exists()


@pytest.mark.parametrize(
    (
        "config",
        "haproxy",
        "overrides",
    ),
    [
        (
            '{"INVALID": 1}\n',
            None,
            {},
        ),
        (
            NEW,
            FRONTED_CFG + "    INVALID\n",
            {"HAPROXY_INSTALLED": "1"},
        ),
        (
            NEW,
            None,
            {"CONFIG_NEW": "0" * 64},
        ),
    ],
    ids=[
        "xray-test",
        "haproxy-check",
        "staged-hash",
    ],
)
def test_rejection_leaves_live_untouched(
    node: FakeNode,
    config: str,
    haproxy: str | None,
    overrides: dict[str, str],
) -> None:
    node.config.write_text(OLD)
    node.haproxy_cfg.write_text(OLD_FRONTED_CFG)
    node.stage_file("config.json", config)
    if haproxy is not None:
        node.stage_file("haproxy.cfg", haproxy)

    assert node.apply(**overrides) == "rejected"
    assert node.config.read_text() == OLD
    assert node.haproxy_cfg.read_text() == OLD_FRONTED_CFG
    assert not [call for call in node.calls("sudo") if call.startswith("mv ")]


def test_stage_with_parent_segment_is_refused_before_cleanup(node: FakeNode) -> None:
    victim = node.run_dir / "keep"
    victim.mkdir()
    node.stage_file("config.json", NEW)

    done = node.invoke("apply", node.params(STAGE=f"{node.stage}/../keep"))

    assert done.returncode == 2
    assert victim.is_dir()
    assert (node.stage / "config.json").exists()


def test_unhealthy_after_swap_rolls_back(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", '{"UNHEALTHY": 1}\n')

    assert node.apply() == "rolled_back"
    assert node.config.read_text() == OLD


def test_failed_rollback_is_reported(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)
    (node.logs / "xray-down").touch()

    assert node.apply() == "rollback_failed"


def test_rollback_removes_file_that_had_no_previous_version(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", '{"UNHEALTHY": 1}\n')
    node.stage_file("haproxy.cfg", FRONTED_CFG)

    assert node.apply(HAPROXY_INSTALLED="1") == "rolled_back"
    assert node.config.read_text() == OLD
    assert not node.haproxy_cfg.exists()


def test_unhealthy_without_previous_files(node: FakeNode) -> None:
    node.stage_file("config.json", '{"UNHEALTHY": 1}\n')

    assert node.apply() == "unhealthy_no_previous"


@pytest.mark.parametrize("drift", [{"CONFIG_BEFORE": "0" * 64}, {"EXPECT_COMMIT": "e" * 40}])
def test_changed_live_state_stops_unless_forced(node: FakeNode, drift: dict[str, str]) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)

    assert node.apply(**drift) == "plan_changed"
    assert node.config.read_text() == OLD
    node.stage.mkdir()
    node.stage_file("config.json", NEW)
    assert node.apply(**drift, FORCE="1") == "applied"


def test_missing_xray_is_prerequisite(node: FakeNode) -> None:
    node.xray_bin.unlink()
    node.stage_file("config.json", NEW)

    assert node.apply() == "prerequisite"


def test_held_lock_times_out_without_changes(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)
    holder = hold_lock(node, 10)
    try:
        assert node.apply(LOCK_WAIT="1") == "locked"
    finally:
        os.killpg(holder.pid, signal.SIGKILL)
        holder.wait()
    assert node.config.read_text() == OLD


def test_new_binary_validates_new_config_with_one_restart(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", '{"NEEDS_NEW_XRAY": 1}\n')
    node.stage_xray(NEW_BUILD)

    assert node.apply(XRAY_EXPECT=f"build:{NEW_BUILD}") == "applied"
    assert NEW_BUILD in node.xray_bin.read_text()
    assert node.service_actions().count("restart xray") == 1


def test_staged_binary_must_report_pinned_build(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.stage_xray(NEW_BUILD)

    assert node.apply(XRAY_EXPECT=f"build:{'f' * 40}") == "rejected"
    assert NEW_BUILD not in node.xray_bin.read_text()


@pytest.mark.parametrize(
    (
        "installed",
        "cfg",
        "actions",
    ),
    [
        (
            "0",
            None,
            ["restart xray"],
        ),
        (
            "1",
            NOOP_CFG,
            ["disable --now haproxy", "restart xray"],
        ),
        (
            "1",
            FRONTED_CFG,
            [
                "restart xray",
                "enable --now haproxy",
                "reload haproxy",
            ],
        ),
    ],
)
def test_service_order_follows_haproxy_table(
    node: FakeNode,
    installed: str,
    cfg: str | None,
    actions: list[str],
) -> None:
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)
    if cfg is not None:
        node.stage_file("haproxy.cfg", cfg)

    assert node.apply(HAPROXY_INSTALLED=installed) == "applied"
    assert node.service_actions() == actions
    checked = [call for call in node.calls("sudo") if call.startswith("/usr/sbin/haproxy -c")]
    assert bool(checked) == (cfg == FRONTED_CFG)


def test_wanted_haproxy_is_part_of_health(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.haproxy_cfg.write_text(OLD_FRONTED_CFG)
    node.stage_file("config.json", NEW)
    node.stage_file("haproxy.cfg", FRONTED_CFG)
    (node.logs / "haproxy-down").touch()

    assert node.apply(HAPROXY_INSTALLED="1") == "rollback_failed"
    assert node.haproxy_cfg.read_text() == OLD_FRONTED_CFG


def test_sudo_argv_stays_within_deployment_sudoers(node: FakeNode) -> None:
    node.config.write_text(OLD)
    node.haproxy_cfg.write_text(NOOP_CFG)
    node.stage_file("config.json", '{"UNHEALTHY": 1}\n')
    node.stage_file("haproxy.cfg", FRONTED_CFG)
    node.stage_xray(NEW_BUILD)

    assert node.apply(HAPROXY_INSTALLED="1", XRAY_EXPECT=f"build:{NEW_BUILD}") == "rolled_back"
    calls = node.calls("sudo")
    assert calls
    for call in calls:
        assert call in ALLOWED_EXACT or call.startswith(("mv ", "/usr/sbin/haproxy ")), call


def test_backups_keep_last_three_runs(node: FakeNode) -> None:
    for age, name in enumerate(
        (
            "old4",
            "old3",
            "old2",
            "old1",
        )
    ):
        path = node.base / "backup" / name
        path.mkdir(parents=True)
        stamp = time.time() - 1000 + age * 100
        os.utime(path, (stamp, stamp))
    node.config.write_text(OLD)
    node.stage_file("config.json", NEW)

    assert node.apply() == "applied"
    assert sorted(p.name for p in (node.base / "backup").iterdir()) == [
        "old1",
        "old2",
        "r1",
    ]
