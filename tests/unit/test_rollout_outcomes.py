"""Payload results and run exit codes."""

import pytest

from astrarium.components.rollout.outcomes import PAYLOAD_RESULTS, Outcome, Status, run_exit_code
from astrarium.errors import ExitCode


pytestmark = pytest.mark.unit


def test_exit_ok_when_nothing_failed() -> None:
    outcomes = {
        "a": Outcome(Status.OK),
        "b": Outcome(Status.UNCHANGED),
        "c": Outcome(Status.SKIPPED, "not a HexRift node"),
    }

    assert run_exit_code(outcomes) is ExitCode.OK


@pytest.mark.parametrize("bad", [Outcome(Status.FAILED, "rejected"), Outcome(Status.NOT_ATTEMPTED)])
def test_exit_partial_on_failed_or_not_attempted(bad: Outcome) -> None:
    assert run_exit_code({"a": Outcome(Status.OK), "b": bad}) is ExitCode.PARTIAL


def test_exit_refused_when_plan_changed() -> None:
    outcomes = {"a": Outcome(Status.FAILED, "rejected"), "b": PAYLOAD_RESULTS["plan_changed"]}

    assert run_exit_code(outcomes) is ExitCode.REFUSED


def test_only_applied_payload_result_is_ok() -> None:
    ok = {name for name, outcome in PAYLOAD_RESULTS.items() if outcome.status is Status.OK}

    assert ok == {"applied"}
    assert {
        "rejected",
        "rolled_back",
        "rollback_failed",
        "unhealthy_no_previous",
        "plan_changed",
        "prerequisite",
    } <= set(PAYLOAD_RESULTS)
