"""Cast batches from rollout schedule: canary, then jump node alone, then one wave per region position."""

from __future__ import annotations

from astrarium.components.rollout.schedule import Schedule


def cast_batches(schedule: Schedule) -> list[list[str]]:
    """One cast per batch, regions advance in parallel, nodes of one region in sequence."""

    batches: list[list[str]] = []
    seen: set[str] = set()
    if schedule.canary is not None:
        batches.append([schedule.canary])
        seen.add(schedule.canary)
    for node_id in schedule.alone:
        if node_id not in seen:
            batches.append([node_id])
            seen.add(node_id)
    queues = [
        [node_id for node_id in schedule.regions[region] if node_id not in seen] for region in sorted(schedule.regions)
    ]
    depth = max((len(queue) for queue in queues), default=0)
    for index in range(depth):
        batches.append([queue[index] for queue in queues if index < len(queue)])
    return batches
