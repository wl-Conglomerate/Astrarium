"""Canary, jump-alone and region scheduling."""

import asyncio
import logging

import pytest

from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.schedule import Schedule, build_schedule, run_schedule
from astrarium.components.rollout.selection import Selection
from astrarium.errors import UsageProblem
from tests.support.nodes import make_node


pytestmark = pytest.mark.unit


class Recorder:
    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)

    def __init__(self, results: dict[str, Outcome] | None = None) -> None:
        self.results = results if results is not None else {}
        self.calls: list[str] = []
        self.sleeps: list[float] = []

    async def fn(self, node_id: str) -> Outcome:
        self.calls.append(node_id)
        return self.results.get(node_id, Outcome(Status.OK))


def test_failed_canary_leaves_rest_not_attempted() -> None:
    rec = Recorder({"c": Outcome(Status.FAILED, "rejected")})
    schedule = Schedule(
        canary="c",
        regions={"nl": ["a", "b"], "de": ["d"]},
        alone=[],
    )

    outcomes = asyncio.run(
        run_schedule(
            schedule,
            rec.fn,
            stagger=10,
            canary_wait=30,
            sleep=rec.sleep,
        )
    )

    assert rec.calls == ["c"]
    assert outcomes["c"].status is Status.FAILED
    assert {
        outcomes[node].status
        for node in (
            "a",
            "b",
            "d",
        )
    } == {Status.NOT_ATTEMPTED}


def test_canary_failing_verify_after_soak_aborts() -> None:
    rec = Recorder()

    async def verify(node_id: str) -> bool:
        return False

    schedule = Schedule(
        canary="c",
        regions={"nl": ["a"]},
        alone=[],
    )
    outcomes = asyncio.run(
        run_schedule(
            schedule,
            rec.fn,
            stagger=10,
            canary_wait=30,
            verify=verify,
            sleep=rec.sleep,
        )
    )

    assert rec.sleeps == [30]
    assert outcomes["c"].status is Status.FAILED
    assert outcomes["a"].status is Status.NOT_ATTEMPTED


def test_canary_verify_exception_fails_closed_and_logs_masked(caplog: pytest.LogCaptureFixture) -> None:
    rec = Recorder()

    async def verify(node_id: str) -> bool:
        raise RuntimeError("hunter2-secret")

    schedule = Schedule(
        canary="c",
        regions={"nl": ["a"]},
        alone=[],
    )
    with caplog.at_level(logging.WARNING, logger="astrarium.components.rollout.schedule"):
        outcomes = asyncio.run(
            run_schedule(
                schedule,
                rec.fn,
                stagger=10,
                canary_wait=0,
                verify=verify,
                sleep=rec.sleep,
            )
        )

    assert outcomes["c"].status is Status.FAILED
    assert outcomes["a"].status is Status.NOT_ATTEMPTED
    assert any(record.levelno == logging.WARNING for record in caplog.records)
    assert "hunter2-secret" not in caplog.text


def test_canary_verify_exception_logs_masked_message_when_mask_given(caplog: pytest.LogCaptureFixture) -> None:
    rec = Recorder()

    async def verify(node_id: str) -> bool:
        raise RuntimeError("hunter2-secret")

    def mask(text: str) -> str:
        return text.replace("hunter2-secret", "***")

    schedule = Schedule(
        canary="c",
        regions={"nl": ["a"]},
        alone=[],
    )
    with caplog.at_level(logging.WARNING, logger="astrarium.components.rollout.schedule"):
        outcomes = asyncio.run(
            run_schedule(
                schedule,
                rec.fn,
                stagger=10,
                canary_wait=0,
                verify=verify,
                mask=mask,
                sleep=rec.sleep,
            )
        )

    assert outcomes["c"].status is Status.FAILED
    assert "***" in caplog.text
    assert "hunter2-secret" not in caplog.text


def test_regions_run_in_parallel_and_stagger_within_region() -> None:
    started = asyncio.Event()
    sleeps: list[float] = []

    async def fn(node_id: str) -> Outcome:
        if node_id == "nl1":
            await asyncio.wait_for(started.wait(), timeout=1)
        if node_id == "de1":
            started.set()
        return Outcome(Status.OK)

    async def sleep(seconds: float) -> None:
        sleeps.append(seconds)

    schedule = Schedule(
        canary=None,
        regions={
            "nl": [
                "nl1",
                "nl2",
                "nl3",
            ],
            "de": ["de1"],
        },
        alone=[],
    )
    outcomes = asyncio.run(
        run_schedule(
            schedule,
            fn,
            stagger=10,
            canary_wait=0,
            sleep=sleep,
        )
    )

    assert set(outcomes) == {
        "nl1",
        "nl2",
        "nl3",
        "de1",
    }
    assert all(outcome.status is Status.OK for outcome in outcomes.values())
    assert sleeps == [10, 10]


def test_exception_fails_only_that_node() -> None:
    async def fn(node_id: str) -> Outcome:
        if node_id == "a":
            raise RuntimeError("boom")
        return Outcome(Status.OK)

    async def sleep(seconds: float) -> None:
        return None

    schedule = Schedule(
        canary=None,
        regions={"nl": ["a", "b"]},
        alone=[],
    )
    outcomes = asyncio.run(
        run_schedule(
            schedule,
            fn,
            stagger=1,
            canary_wait=0,
            sleep=sleep,
        )
    )

    assert outcomes["a"].status is Status.FAILED
    assert outcomes["b"].status is Status.OK


def test_build_schedule_puts_jump_alone_and_rejects_unselected_canary() -> None:
    nodes = {"edge": make_node("edge", region="edge"), "nlA00": make_node("nlA00")}
    selection = Selection(nodes=["edge", "nlA00"], skipped={})

    schedule = build_schedule(
        selection,
        nodes,
        canary=None,
        jump="edge",
    )

    assert schedule.alone == ["edge"]
    assert schedule.regions == {"nl": ["nlA00"]}
    with pytest.raises(UsageProblem):
        build_schedule(
            selection,
            nodes,
            canary="deA00",
            jump=None,
        )
