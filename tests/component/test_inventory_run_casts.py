"""Cast orchestration with fake casts and scripted transports."""

import asyncio
from dataclasses import replace

import pytest

from astrarium.components.inventory.cast import CastResult
from astrarium.components.inventory.controller import CastPlan
from astrarium.components.inventory.paths import PATH_PROBE
from astrarium.components.rollout.outcomes import Status
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.secrets.masking import ValueMasker
from astrarium.runtime import RuntimeDir
from tests.support.fleet import TELEMT_SECRET, FakeRunner, TransportPool, controller_with, fleet, make_control


pytestmark = pytest.mark.component

DEPLOY_ACCESS = "/pkg/astrarium/runes/deploy_access.py"

UFW = "netsec | Enable UFW firewall"

HOP_KEYS = f"{DEPLOY_ACCESS} | Write github_actions authorized_keys"


async def _no_sleep(_seconds: float) -> None:
    return None


def _statuses(reports, *node_ids):
    return {reports[node_id].outcome.status for node_id in node_ids}


def _plan(batches, *, stages=None, canary=None, dry=False):
    members = [node_id for batch in batches for node_id in batch]
    return CastPlan(
        batches=batches,
        stages=[{node_id: () for node_id in members}] if stages is None else stages,
        identity="admin",
        via="jump",
        canary=canary,
        canary_wait=0.0,
        stagger=0.0,
        dry=dry,
    )


def _run(runner, pool, plan, *, verify=None, masker=None, nodes=None, echo=None):
    with RuntimeDir() as runtime:
        return asyncio.run(
            controller_with(runner, pool).run_casts(
                runtime,
                fleet() if nodes is None else nodes,
                make_control(),
                plan,
                ValueMasker() if masker is None else masker,
                verify=verify,
                echo=echo,
                sleep=_no_sleep,
            )
        )


def test_canary_failure_leaves_rest_not_attempted():
    runner = FakeRunner(script=lambda limits, runes: CastResult(1, list(limits), {}, 1))
    reports = _run(
        runner,
        TransportPool(),
        _plan([["nlA00"], ["nlA01", "mskA10"]], canary="nlA00"),
    )
    assert reports["nlA00"].outcome.status is Status.FAILED
    assert _statuses(
        reports,
        "nlA01",
        "mskA10",
    ) == {Status.NOT_ATTEMPTED}
    assert [call[0] for call in runner.calls] == [["nlA00"]]


@pytest.mark.parametrize("rc", [75, 255])
def test_canary_blocked_by_lock_check_leaves_rest_not_attempted(rc):
    pool = TransportPool()
    pool.get("admin", "jump").replies[("nlA00", "flock")] = CommandResult(
        rc=rc,
        stdout="",
        stderr="",
    )
    runner = FakeRunner()
    reports = _run(
        runner,
        pool,
        _plan([["nlA00"], ["nlA01", "mskA10"]], canary="nlA00"),
    )
    assert reports["nlA00"].outcome.status in {Status.NOT_ATTEMPTED, Status.FAILED}
    assert _statuses(
        reports,
        "nlA01",
        "mskA10",
    ) == {Status.NOT_ATTEMPTED}
    assert runner.calls == []


def test_failed_jump_cast_leaves_rest_not_attempted():
    runner = FakeRunner(script=lambda limits, runes: CastResult(1, list(limits), {}, 1))
    reports = _run(
        runner,
        TransportPool(),
        _plan([["edge"], ["nlA00", "nlA01"]]),
    )
    assert reports["edge"].outcome.status is Status.FAILED
    assert _statuses(
        reports,
        "nlA00",
        "nlA01",
    ) == {Status.NOT_ATTEMPTED}
    assert [call[0] for call in runner.calls] == [["edge"]]


def test_exit_without_failed_hosts_fails_whole_batch_but_listed_failures_stay_local():
    def script(limits, runes):
        if "nlA00" in limits:
            return CastResult(
                1,
                [],
                {},
                0,
            )
        return CastResult(
            1,
            ["mskA10"],
            {"plsA00": ["telemt | Deploy telemt configuration"]},
            1,
        )

    reports = _run(
        FakeRunner(script=script),
        TransportPool(),
        _plan([["nlA00", "nlA01"], ["mskA10", "plsA00"]]),
    )
    assert _statuses(
        reports,
        "nlA00",
        "nlA01",
        "mskA10",
    ) == {Status.FAILED}
    assert reports["plsA00"].outcome.status is Status.OK


def test_second_stage_runs_only_for_hosts_that_passed_the_first():
    members = ["nlA00", "nlA01"]
    stages = [{node_id: () for node_id in members}, {node_id: (DEPLOY_ACCESS,) for node_id in members}]
    runner = FakeRunner(
        script=lambda limits, runes: CastResult(1, ["nlA01"], {}, 1) if not runes else CastResult(0, [], {}, 1)
    )
    reports = _run(
        runner,
        TransportPool(),
        _plan([members], stages=stages),
    )
    assert runner.calls[1][:2] == (["nlA00"], [DEPLOY_ACCESS])
    assert reports["nlA01"].outcome.status is Status.FAILED
    assert reports["nlA00"].outcome.status is Status.UNCHANGED


def test_broken_ssh_login_after_netsec_change_stops_the_rollout():
    runner = FakeRunner(script=lambda limits, runes: CastResult(0, [], {node_id: [UFW] for node_id in limits}, 1))
    pool = TransportPool()
    pool.get("deploy", "jump").replies[("nlA01", PATH_PROBE)] = CommandResult(
        rc=255,
        stdout="",
        stderr="",
    )
    reports = _run(
        runner,
        pool,
        _plan([["nlA00", "nlA01"], ["mskA10"]]),
    )
    assert reports["nlA01"].outcome.status is Status.FAILED
    assert reports["nlA00"].outcome.status is Status.OK
    assert reports["mskA10"].outcome.status is Status.NOT_ATTEMPTED


def test_node_mid_deploy_is_not_attempted_and_left_out_of_the_cast():
    pool = TransportPool()
    pool.get("admin", "jump").replies[("nlA00", "flock")] = CommandResult(
        rc=75,
        stdout="",
        stderr="",
    )
    runner = FakeRunner()
    reports = _run(
        runner,
        pool,
        _plan([["nlA00", "nlA01"]]),
    )
    assert reports["nlA00"].outcome.status is Status.NOT_ATTEMPTED
    assert runner.calls[0][0] == ["nlA01"]


def test_dry_run_skips_lock_and_login_checks():
    runner = FakeRunner(script=lambda limits, runes: CastResult(0, [], {node_id: [UFW] for node_id in limits}, 1))
    pool = TransportPool()
    reports = _run(
        runner,
        pool,
        _plan([["nlA00"]], dry=True),
    )
    assert reports["nlA00"].outcome.status is Status.OK
    assert reports["nlA00"].changed == [UFW]
    assert runner.calls[0][2] is True
    assert all(not transport.calls for transport in pool.transports.values())


def test_canary_verification_failure_aborts_the_rest():
    async def verify(batch):
        return {"nlA00": "telemt: installed 3.5.6, pinned 3.5.7"} if batch == ["nlA00"] else {}

    reports = _run(
        FakeRunner(),
        TransportPool(),
        _plan([["nlA00"], ["nlA01"]], canary="nlA00"),
        verify=lambda transport: verify,
    )
    assert reports["nlA00"].outcome.status is Status.FAILED
    assert reports["nlA01"].outcome.status is Status.NOT_ATTEMPTED


def test_failed_batch_keeps_masked_log_tail():
    masker = ValueMasker()
    masker.add(TELEMT_SECRET)
    runner = FakeRunner(
        script=lambda limits, runes: CastResult(1, [], {}, 0),
        stderr_lines=[f"--> Starting operation: telemt | Deploy telemt configuration (users={TELEMT_SECRET})"],
    )
    reports = _run(
        runner,
        TransportPool(),
        _plan([["plsA00"]]),
        masker=masker,
    )
    tail = reports["plsA00"].log_tail
    assert tail
    assert not any(TELEMT_SECRET in line for line in tail)


def test_stderr_secret_reaches_echo_callback_masked():
    """run_streaming's stderr never reaches terminal except through masker.mask."""

    masker = ValueMasker()
    masker.add(TELEMT_SECRET)
    runner = FakeRunner(stderr_lines=[f"--> users={TELEMT_SECRET}"])
    seen: list[str] = []
    _run(
        runner,
        TransportPool(),
        _plan([["nlA00"]]),
        masker=masker,
        echo=seen.append,
    )
    assert seen
    assert not any(TELEMT_SECRET in line for line in seen)


def test_jump_batch_path_failure_on_a_later_node_leaves_it_failed():
    """Jump-batch path check probes whole run scope, break named for later node stays on it
    (not overwritten by abort's NOT_ATTEMPTED sweep) and fails jump too.
    """

    runner = FakeRunner(script=lambda limits, runes: CastResult(0, [], {node_id: [UFW] for node_id in limits}, 1))
    pool = TransportPool()
    pool.get("deploy", "jump").replies[("nlA01", PATH_PROBE)] = CommandResult(
        rc=255,
        stdout="",
        stderr="",
    )
    reports = _run(
        runner,
        pool,
        _plan([["edge"], ["nlA00", "nlA01"]]),
    )
    assert reports["edge"].outcome.status is Status.FAILED
    assert reports["nlA01"].outcome.status is Status.FAILED
    assert reports["nlA00"].outcome.status is Status.NOT_ATTEMPTED


@pytest.mark.parametrize(
    (
        "rc",
        "edge",
        "rest",
    ),
    [
        (
            1,
            Status.OK,
            Status.OK,
        ),
        (
            255,
            Status.FAILED,
            Status.NOT_ATTEMPTED,
        ),
    ],
)
def test_jump_batch_checks_deploy_hop_on_the_bastion_auth_only(rc, edge, rest):
    """Hop login runs forced nologin (exit 1), only transport failure fails bastion and stops run."""

    runner = FakeRunner(script=lambda limits, runes: CastResult(0, [], {node_id: [HOP_KEYS] for node_id in limits}, 1))
    pool = TransportPool()
    pool.get("deploy", "jump").replies[("edge", PATH_PROBE)] = CommandResult(
        rc=rc,
        stdout="",
        stderr="",
    )
    reports = _run(
        runner,
        pool,
        _plan([["edge"], ["nlA00"]]),
    )
    assert ("edge", PATH_PROBE) in pool.get("deploy", "jump").calls
    assert reports["edge"].outcome.status is edge
    assert reports["nlA00"].outcome.status is rest


def test_node_without_host_keys_outside_limit_does_not_block_the_cast():
    """Fleet node missing host_keys never enters this run's ssh scope unless target or jump."""

    nodes = dict(fleet())
    nodes["plsA00"] = replace(nodes["plsA00"], host_keys={})
    reports = _run(
        FakeRunner(),
        TransportPool(),
        _plan([["nlA00"]]),
        nodes=nodes,
    )
    assert reports["nlA00"].outcome.status is Status.UNCHANGED
