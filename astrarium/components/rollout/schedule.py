"""Canary, jump-alone and per-region scheduling."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.errors import UsageProblem

from .outcomes import CANARY_FAILED, Outcome, Status
from .selection import Selection


LOG = logging.getLogger(__name__)

JUMP_FAILED = Outcome(Status.NOT_ATTEMPTED, "jump node failed")


@dataclass(frozen=True)
class Schedule:
    canary: str | None
    regions: dict[str, list[str]]
    alone: list[str]
    """Jump node when selected: runs by itself before any region."""


def build_schedule(
    selection: Selection,
    nodes: Mapping[str, EffectiveNode],
    canary: str | None,
    jump: str | None,
) -> Schedule:
    """Canary and jump node out of regions, regions in selection order, UsageProblem for unselected canary."""

    if canary is not None and canary not in selection.nodes:
        raise UsageProblem(f"canary {canary} is not among the selected nodes")
    alone = [jump] if jump is not None and jump in selection.nodes and jump != canary else []
    regions: dict[str, list[str]] = {}
    for node_id in selection.nodes:
        if node_id != canary and node_id not in alone:
            regions.setdefault(nodes[node_id].region, []).append(node_id)
    return Schedule(
        canary=canary,
        regions=regions,
        alone=alone,
    )


def _dropped(
    action: str,
    node_id: str,
    exc: Exception,
    mask: Callable[[str], str] | None = None,
) -> str:
    """Warn with masked message when mask given, else type name only, return type name for reason."""

    detail = mask(str(exc)) if mask is not None else type(exc).__name__
    LOG.warning(
        f"{action} {node_id}: {detail}",
        exc_info=LOG.isEnabledFor(logging.DEBUG),
    )
    return type(exc).__name__


async def run_schedule(
    schedule: Schedule,
    fn: Callable[[str], Awaitable[Outcome]],
    *,
    stagger: float,
    canary_wait: float,
    verify: Callable[[str], Awaitable[bool]] | None = None,
    mask: Callable[[str], str] | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> dict[str, Outcome]:
    """Canary, then jump node, then regions in parallel (stagger inside region), one outcome per node.

    `mask`, when given, masks swallowed verify/attempt exception message for warning log
    (otherwise only exception type name is logged).
    """

    outcomes: dict[str, Outcome] = {}
    rest = [*schedule.alone, *(node_id for ids in schedule.regions.values() for node_id in ids)]

    async def attempt(node_id: str) -> Outcome:
        try:
            return await fn(node_id)
        except Exception as e:
            return Outcome(Status.FAILED, f"internal error: {_dropped('run', node_id, e, mask)}")

    async def verified(node_id: str) -> bool:
        if verify is None:
            return True
        try:
            return await verify(node_id)
        except Exception as e:
            _dropped(
                "verify",
                node_id,
                e,
                mask,
            )
            return False

    def abort(outcome: Outcome) -> dict[str, Outcome]:
        for node_id in rest:
            outcomes.setdefault(node_id, outcome)
        return outcomes

    if schedule.canary is not None:
        result = await attempt(schedule.canary)
        if result.status is Status.OK:
            if canary_wait > 0:
                await sleep(canary_wait)
            if not await verified(schedule.canary):
                result = Outcome(Status.FAILED, "unhealthy after canary soak")
        outcomes[schedule.canary] = result
        if result.status is Status.FAILED:
            return abort(CANARY_FAILED)

    for node_id in schedule.alone:
        outcomes[node_id] = await attempt(node_id)
        if outcomes[node_id].status is Status.FAILED:
            return abort(JUMP_FAILED)

    async def region(ids: list[str]) -> None:
        for index, node_id in enumerate(ids):
            if index:
                await sleep(stagger)
            outcomes[node_id] = await attempt(node_id)

    await asyncio.gather(*(region(ids) for ids in schedule.regions.values()))
    return outcomes
