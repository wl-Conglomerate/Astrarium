"""Per-node outcomes of deploy runs and run exit codes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from astrarium.errors import ExitCode


class Status(StrEnum):
    OK = "ok"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    FAILED = "failed"
    NOT_ATTEMPTED = "not_attempted"


@dataclass(frozen=True)
class Outcome:
    status: Status
    reason: str | None = None

    def __str__(self) -> str:
        return f"{self.status.name}({self.reason})" if self.reason else self.status.name


PLAN_CHANGED = Outcome(Status.FAILED, "plan changed")

UNKNOWN_STATE = Outcome(Status.FAILED, "unknown state")

OLDER_COMMIT = Outcome(Status.FAILED, "older commit")

UNREACHABLE = Outcome(Status.FAILED, "unreachable")

WOULD_CHANGE = Outcome(Status.OK, "would change")

CANARY_FAILED = Outcome(Status.NOT_ATTEMPTED, "canary failed")

PREREQUISITE = Outcome(Status.FAILED, "prerequisite")

RECORDED_COMMIT_UNKNOWN = Outcome(Status.FAILED, "recorded commit unknown")

ROTATION_INCOMPLETE = Outcome(Status.NOT_ATTEMPTED, "exit rotation incomplete")

PAYLOAD_RESULTS: Mapping[str, Outcome] = MappingProxyType(
    {
        "applied": Outcome(Status.OK),
        "rejected": Outcome(Status.FAILED, "rejected"),
        "rolled_back": Outcome(Status.FAILED, "rolled back"),
        "rollback_failed": Outcome(Status.FAILED, "rollback failed"),
        "unhealthy_no_previous": Outcome(Status.FAILED, "unhealthy, nothing to roll back"),
        "plan_changed": PLAN_CHANGED,
        "prerequisite": PREREQUISITE,
        "locked": Outcome(Status.FAILED, "locked by another run"),
        "unknown": UNKNOWN_STATE,
    }
)
"""Payload `result=` values -> outcomes."""


def run_exit_code(outcomes: Mapping[str, Outcome]) -> ExitCode:
    """REFUSED when any node saw its plan change, PARTIAL on any failure or abort, else OK."""

    values = list(outcomes.values())
    if PLAN_CHANGED in values:
        return ExitCode.REFUSED
    if any(outcome.status in (Status.FAILED, Status.NOT_ATTEMPTED) for outcome in values):
        return ExitCode.PARTIAL
    return ExitCode.OK
