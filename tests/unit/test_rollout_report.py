"""Run ids and JSON view of outcomes."""

import pytest

from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.report import RUN_ID_PATTERN, new_run_id, outcomes_json


pytestmark = pytest.mark.unit


def test_run_ids_are_remote_path_safe() -> None:
    assert RUN_ID_PATTERN.fullmatch(new_run_id())


def test_json_lists_every_node_with_status_and_reason() -> None:
    data = outcomes_json({"a": Outcome(Status.OK), "b": Outcome(Status.FAILED, "rejected")})

    assert data == [
        {
            "node": "a",
            "status": "ok",
            "reason": None,
        },
        {
            "node": "b",
            "status": "failed",
            "reason": "rejected",
        },
    ]
