"""`--limit` matching: union, unmatched entries, roles, non-HexRift nodes."""

import pytest

from astrarium.components.rollout.selection import select
from astrarium.errors import Refused, UsageProblem
from tests.support.nodes import make_node


pytestmark = pytest.mark.unit


@pytest.fixture
def fleet():
    return {
        "nlA00": make_node("nlA00", role="exit"),
        "nlA01": make_node("nlA01", role="exit"),
        "mskA10": make_node(
            "mskA10",
            role="relay",
            root_role="hub",
        ),
        "mskP00": make_node("mskP00", role="pulsar"),
        "edge": make_node(
            "edge",
            role="bastion",
            region="edge",
        ),
    }


def test_overlapping_entries_select_union(fleet) -> None:
    selection = select(
        fleet,
        "nl, nlA00",
        hexrift_only=True,
    )

    assert selection.nodes == ["nlA00", "nlA01"]


def test_unmatched_entry_is_refused(fleet) -> None:
    with pytest.raises(Refused):
        select(
            fleet,
            "nlA00,zz",
            hexrift_only=True,
        )


def test_role_entry_matches_role_and_root_role(fleet) -> None:
    assert select(
        fleet,
        "@hub",
        hexrift_only=True,
    ).nodes == ["mskA10"]
    assert select(
        fleet,
        "@relay",
        hexrift_only=True,
    ).nodes == ["mskA10"]


def test_matched_non_hexrift_nodes_are_skipped(fleet) -> None:
    selection = select(
        fleet,
        "msk",
        hexrift_only=True,
    )

    assert selection.nodes == ["mskA10"]
    assert set(selection.skipped) == {"mskP00"}


def test_no_limit_selects_every_deployable_node(fleet) -> None:
    assert select(
        fleet,
        None,
        hexrift_only=True,
    ).nodes == [
        "nlA00",
        "nlA01",
        "mskA10",
    ]
    assert len(
        select(
            fleet,
            None,
            hexrift_only=False,
        ).nodes
    ) == len(fleet)


@pytest.mark.parametrize("limit", ["", "  ,  "])
def test_blank_limit_is_refused_not_treated_as_no_limit(fleet, limit: str) -> None:
    with pytest.raises(UsageProblem):
        select(
            fleet,
            limit,
            hexrift_only=True,
        )
