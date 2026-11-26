"""Repo discovery and dirty-tree guard."""

import subprocess
from pathlib import Path

import pytest

from astrarium.errors import ExternalToolError, InvalidManifest, Refused
from astrarium.repo import Repo, ensure_clean


pytestmark = pytest.mark.component

GIT = (
    "git",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
)


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        [
            *GIT,
            "-C",
            str(root),
            *args,
        ],
        check=True,
        capture_output=True,
    )


def _committed_repo(root: Path) -> Repo:
    (root / "secrets" / "keys").mkdir(parents=True)
    (root / "astrarium.yaml").write_text("deployment: {name: test}\nnodes: {}\n")
    (root / "secrets" / "keys" / "nlA00.yaml").write_text("sops: {}\n")
    (root / "notes.md").write_text("free text\n")
    _git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    _git(
        root,
        "add",
        "-A",
    )
    _git(
        root,
        "commit",
        "-q",
        "-m",
        "init",
    )
    return Repo(root)


def test_dirty_paths_cover_guarded_paths_only(tmp_path: Path):
    repo = _committed_repo(tmp_path)
    (tmp_path / "astrarium.yaml").write_text("deployment: {name: other}\nnodes: {}\n")
    (tmp_path / "secrets" / "keys" / "mskA00.yaml").write_text("sops: {}\n")
    (tmp_path / "notes.md").write_text("edited\n")
    assert repo.dirty_paths() == ["astrarium.yaml", "secrets/keys/mskA00.yaml"]


def test_ensure_clean_refuses_dirty_tree_unless_allowed(tmp_path: Path):
    repo = _committed_repo(tmp_path)
    (tmp_path / "secrets" / "keys" / "nlA00.yaml").write_text("sops: {changed: true}\n")
    with pytest.raises(Refused):
        ensure_clean(repo, allow_dirty=False)
    ensure_clean(repo, allow_dirty=True)


def test_ensure_clean_refuses_untracked_repo_rune(tmp_path: Path):
    repo = _committed_repo(tmp_path)
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / "x.py").write_text('"""Local tweak."""\n')
    with pytest.raises(Refused):
        ensure_clean(repo, allow_dirty=False)


def test_ensure_clean_allowed_needs_no_git(tmp_path: Path):
    ensure_clean(Repo(tmp_path), allow_dirty=True)


def test_key_file_rejects_path_like_node_ids(tmp_path: Path):
    with pytest.raises(InvalidManifest):
        Repo(tmp_path).key_file("../escape")


def test_discover_finds_nearest_ancestor_manifest(tmp_path: Path):
    (tmp_path / "astrarium.yaml").write_text("deployment: {name: test}\nnodes: {}\n")
    nested = tmp_path / "a" / "b" / "c"
    nested.mkdir(parents=True)
    assert Repo.discover(nested).root == tmp_path.resolve()


def test_discover_raises_invalid_manifest_without_ancestor_manifest(tmp_path: Path):
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    with pytest.raises(InvalidManifest):
        Repo.discover(nested)


def test_dirty_paths_reports_new_path_of_staged_rename(tmp_path: Path):
    repo = _committed_repo(tmp_path)
    _git(
        tmp_path,
        "mv",
        "secrets/keys/nlA00.yaml",
        "secrets/keys/mskA00.yaml",
    )
    assert repo.dirty_paths() == ["secrets/keys/mskA00.yaml"]


def test_dirty_paths_relative_to_root_in_subdirectory_worktree(tmp_path: Path):
    _git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    deploy = tmp_path / "deploy"
    (deploy / "secrets" / "keys").mkdir(parents=True)
    (deploy / "astrarium.yaml").write_text("deployment: {name: test}\nnodes: {}\n")
    (deploy / "secrets" / "keys" / "nlA00.yaml").write_text("sops: {}\n")
    _git(
        tmp_path,
        "add",
        "-A",
    )
    _git(
        tmp_path,
        "commit",
        "-q",
        "-m",
        "init",
    )
    repo = Repo(deploy)
    (deploy / "astrarium.yaml").write_text("deployment: {name: other}\nnodes: {}\n")
    assert repo.dirty_paths() == ["astrarium.yaml"]


def test_dirty_paths_raises_external_tool_error_without_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = Repo(tmp_path)
    monkeypatch.setenv("PATH", "")
    with pytest.raises(ExternalToolError):
        repo.dirty_paths()


def test_commit_returns_none_without_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = Repo(tmp_path)
    monkeypatch.setenv("PATH", "")
    assert repo.commit() is None
