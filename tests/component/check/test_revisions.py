"""Base revision access through git."""

from __future__ import annotations

from pathlib import Path

import pytest

from astrarium.components.check.revisions import code_diff, materialize_revision, resolve_base
from astrarium.errors import UsageProblem
from tests.support.deployment import git


pytestmark = pytest.mark.component


def _commit(root: Path, message: str) -> str:
    """Stage everything, commit (even empty), return sha."""

    git(
        root,
        "add",
        "-A",
    )
    git(
        root,
        "commit",
        "-q",
        "--allow-empty",
        "-m",
        message,
    )
    return git(
        root,
        "rev-parse",
        "HEAD",
    )


def test_materialize_revision_copies_committed_deployment_files_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    (root / "astrarium.yaml").write_text("committed\n")
    (root / "secrets" / "keys").mkdir(parents=True)
    (root / "secrets" / "keys" / "nlA00.yaml").write_text("key\n")
    (root / "README.md").write_text("unrelated\n")
    sha = _commit(root, "base")
    (root / "astrarium.yaml").write_text("working tree\n")

    dest = materialize_revision(
        root,
        sha,
        tmp_path / "base",
    )

    assert (dest / "astrarium.yaml").read_text() == "committed\n"
    assert (dest / "secrets" / "keys" / "nlA00.yaml").read_text() == "key\n"
    assert not (dest / "README.md").exists()
    assert not (dest / "topology.yaml").exists()


def test_materialize_revision_works_when_deployment_root_is_nested_in_a_bigger_worktree(tmp_path: Path) -> None:
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    deploy = tmp_path / "deploy"
    (deploy / "secrets" / "keys").mkdir(parents=True)
    (deploy / "astrarium.yaml").write_text("committed\n")
    (deploy / "secrets" / "keys" / "nlA00.yaml").write_text("key\n")
    sha = _commit(tmp_path, "base")

    dest = materialize_revision(
        deploy,
        sha,
        tmp_path / "base-out",
    )

    assert (dest / "astrarium.yaml").read_text() == "committed\n"
    assert (dest / "secrets" / "keys" / "nlA00.yaml").read_text() == "key\n"


def test_resolve_base_is_merge_base_with_head(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    fork_point = _commit(root, "one")
    git(
        root,
        "switch",
        "-q",
        "-c",
        "feature",
    )
    _commit(root, "feature work")
    git(
        root,
        "switch",
        "-q",
        "main",
    )
    _commit(root, "main moves on")
    git(
        root,
        "switch",
        "-q",
        "feature",
    )

    assert resolve_base(root, "main") == fork_point


def test_resolve_base_rejects_unknown_ref(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    _commit(root, "one")

    with pytest.raises(UsageProblem):
        resolve_base(root, "origin/does-not-exist")


def test_resolve_base_without_shared_history_is_usage_problem(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    _commit(root, "one")
    git(
        root,
        "switch",
        "-q",
        "--orphan",
        "feature",
    )
    _commit(root, "unrelated")

    with pytest.raises(UsageProblem):
        resolve_base(root, "main")


def test_code_diff_covers_runes_and_workflows_only(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    sha = _commit(root, "one")
    (root / "runes").mkdir()
    (root / "runes" / "extra.py").write_text("print('rune')\n")
    (root / "astrarium.yaml").write_text("not code\n")
    _commit(root, "two")

    diff = code_diff(root, sha)

    assert "runes/extra.py" in diff
    assert "astrarium.yaml" not in diff
