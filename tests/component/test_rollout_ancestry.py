"""Deploying commit and ancestry of commit recorded per node."""

import pytest

from astrarium.components.rollout.ancestry import descends_from, head_commit_of
from astrarium.errors import UsageProblem
from tests.support.deployment import git


pytestmark = pytest.mark.component


def test_ancestry_of_recorded_commits(tmp_path) -> None:
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    with pytest.raises(UsageProblem):
        head_commit_of(tmp_path)
    git(
        tmp_path,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "base",
    )
    base = head_commit_of(tmp_path)
    git(
        tmp_path,
        "switch",
        "-q",
        "-c",
        "side",
    )
    git(
        tmp_path,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "side",
    )
    side = head_commit_of(tmp_path)
    git(
        tmp_path,
        "switch",
        "-q",
        "main",
    )
    git(
        tmp_path,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        "next",
    )
    head = head_commit_of(tmp_path)

    assert (
        descends_from(
            tmp_path,
            base,
            head,
        )
        is True
    )
    assert (
        descends_from(
            tmp_path,
            head,
            head,
        )
        is True
    )
    assert (
        descends_from(
            tmp_path,
            side,
            head,
        )
        is False
    )
    assert (
        descends_from(
            tmp_path,
            "f" * 40,
            head,
        )
        is None
    )
