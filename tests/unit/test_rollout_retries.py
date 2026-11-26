"""Transport retries: exit 255 only, exponential backoff with jitter."""

import asyncio

import pytest

from astrarium.components.rollout.transport import CommandResult, with_retries


pytestmark = pytest.mark.unit


def scripted(*rcs: int):
    calls = []

    async def call() -> CommandResult:
        calls.append(1)
        return CommandResult(
            rcs[len(calls) - 1],
            "",
            "",
        )

    return call, calls


def test_retries_transport_failures_with_growing_backoff() -> None:
    call, calls = scripted(
        255,
        255,
        0,
    )
    delays: list[float] = []

    async def sleep(seconds: float) -> None:
        delays.append(seconds)

    result = asyncio.run(
        with_retries(
            call,
            attempts=3,
            base_delay=5.0,
            sleep=sleep,
        )
    )

    assert result.rc == 0
    assert len(calls) == 3
    assert 5.0 <= delays[0] <= 10.0
    assert 10.0 <= delays[1] <= 15.0


def test_other_exit_codes_are_not_retried() -> None:
    call, calls = scripted(1, 0)

    async def sleep(seconds: float) -> None:
        return None

    result = asyncio.run(with_retries(call, sleep=sleep))

    assert result.rc == 1
    assert len(calls) == 1


def test_gives_up_after_attempts() -> None:
    call, calls = scripted(
        255,
        255,
        255,
    )

    async def sleep(seconds: float) -> None:
        return None

    assert (
        asyncio.run(
            with_retries(
                call,
                attempts=3,
                sleep=sleep,
            )
        ).rc
        == 255
    )
    assert len(calls) == 3
