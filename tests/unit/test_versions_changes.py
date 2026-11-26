"""Effective pin changes between two manifest revisions."""

import pytest

from astrarium.components.versions.changes import check_ref, pin_changes
from astrarium.errors import Refused


pytestmark = pytest.mark.unit

DEFAULTS = {"telemt": "3.4.23", "usque": "4.2.1"}


def _raw(versions=None, **nodes):
    return {
        "versions": {} if versions is None else versions,
        "nodes": {node_id: {"role": "pulsar", "overrides": {"versions": pins}} for node_id, pins in nodes.items()},
    }


def test_changes_follow_node_override_then_global_pin_then_default():
    base = _raw(
        {"telemt": "3.5.6"},
        plsA00={},
        plsA01={"telemt": "3.5.6"},
        mskA10={},
    )
    head = _raw(
        {"telemt": "3.5.7"},
        plsA00={},
        plsA01={"telemt": "3.5.6"},
        mskA10={"usque": "4.3.0"},
        nlA09={},
    )
    changed, new_nodes = pin_changes(
        base,
        head,
        DEFAULTS,
    )
    assert changed == {"plsA00": ["telemt"], "mskA10": ["telemt", "usque"]}
    assert new_nodes == ["nlA09"]


def test_writing_the_default_pin_explicitly_is_no_change():
    assert pin_changes(
        _raw(None, plsA00={}),
        _raw({"telemt": "3.4.23"}, plsA00={}),
        DEFAULTS,
    ) == ({}, [])


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "  ",
        "0" * 40,
        "--output=/tmp/x",
    ],
)
def test_unusable_base_refs_fail_closed(ref):
    with pytest.raises(Refused):
        check_ref(ref)
