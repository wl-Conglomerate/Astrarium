"""Pdsh helpers: pdsh exit-code convention and dshbak-style collapse grouping."""

import pytest

from astrarium.components.pdsh.controller import NodeResult, collapse_groups, pdsh_exit_code


pytestmark = pytest.mark.unit


def result(node_id: str, rc: int = 0, stdout: str = "", stderr: str = "") -> NodeResult:
    return NodeResult(node_id=node_id, rc=rc, stdout=stdout, stderr=stderr)


def test_exit_code_zero_when_all_succeed() -> None:
    assert pdsh_exit_code([result("a"), result("b")]) == 0
    assert pdsh_exit_code([]) == 0


def test_exit_code_counts_failed_nodes() -> None:
    assert pdsh_exit_code([result("a"), result("b", rc=1), result("c", rc=255)]) == 2


def test_exit_code_capped_at_255() -> None:
    results = [result(f"n{i}", rc=1) for i in range(300)]
    assert pdsh_exit_code(results) == 255


def test_collapse_groups_identical_output() -> None:
    results = [
        result("nlA00", stdout="ok\n"),
        result("mskA00", stdout="ok\n"),
        result("nlA20", rc=1, stderr="boom\n"),
    ]
    groups = collapse_groups(results)
    assert [(nodes, r.node_id) for nodes, r in groups] == [(["nlA00", "mskA00"], "nlA00"), (["nlA20"], "nlA20")]


def test_collapse_distinguishes_rc_and_stderr() -> None:
    results = [result("a", stdout="x\n"), result("b", stdout="x\n", stderr="y\n"), result("c", rc=2, stdout="x\n")]
    assert len(collapse_groups(results)) == 3
    assert collapse_groups([]) == []
