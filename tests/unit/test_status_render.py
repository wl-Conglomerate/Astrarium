import io

import pytest
from rich.console import Console

from astrarium.components.status.component import render_status
from astrarium.components.status.controller import MATCH, NodeStatus


pytestmark = pytest.mark.unit


def _render(table) -> str:
    buf = io.StringIO()
    Console(file=buf, width=250).print(table)
    return buf.getvalue()


def test_collapse_groups_nodes_with_identical_status() -> None:
    statuses = {
        "nlA00": NodeStatus(
            "nlA00",
            "exit",
            "nl",
            True,
            MATCH,
            {"telemt": "3.5.6"},
            [],
        ),
        "nlA20": NodeStatus(
            "nlA20",
            "exit",
            "nl",
            True,
            MATCH,
            {"telemt": "3.5.6"},
            [],
        ),
        "mskA00": NodeStatus(
            "mskA00",
            "hub",
            "msk",
            True,
            MATCH,
            {"telemt": "3.5.5"},
            [],
        ),
    }

    text = _render(render_status(statuses, collapse=True))

    assert "nlA00,nlA20" in text
    assert "mskA00" in text


def test_default_keeps_one_row_per_node() -> None:
    statuses = {
        "nlA00": NodeStatus(
            "nlA00",
            "exit",
            "nl",
            True,
            MATCH,
            {"telemt": "3.5.6"},
            [],
        ),
        "nlA20": NodeStatus(
            "nlA20",
            "exit",
            "nl",
            True,
            MATCH,
            {"telemt": "3.5.6"},
            [],
        ),
    }

    text = _render(render_status(statuses))

    assert "nlA00" in text and "nlA20" in text
    assert "nlA00,nlA20" not in text
