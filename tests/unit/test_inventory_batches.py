"""Cast batches: canary alone, then jump alone, then one wave per region position."""

import pytest

from astrarium.components.inventory.batches import cast_batches
from astrarium.components.rollout.schedule import Schedule


pytestmark = pytest.mark.unit


def test_canary_first_then_jump_alone_then_one_wave_per_region_position():
    schedule = Schedule(
        canary="nlA01",
        regions={
            "nl": [
                "nlA00",
                "nlA01",
                "nlA02",
            ],
            "msk": ["mskA10"],
        },
        alone=["edge"],
    )
    batches = cast_batches(schedule)
    assert batches[:2] == [["nlA01"], ["edge"]]
    assert [set(batch) for batch in batches[2:]] == [{"nlA00", "mskA10"}, {"nlA02"}]
    assert sorted(node for batch in batches for node in batch) == [
        "edge",
        "mskA10",
        "nlA00",
        "nlA01",
        "nlA02",
    ]
