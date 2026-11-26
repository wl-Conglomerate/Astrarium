"""Rune names to `nullforge cast -r` arguments."""

from pathlib import Path

import pytest

from astrarium.components.inventory.runes import repo_runes, resolve_rune
from astrarium.errors import InvalidManifest, UsageProblem
from astrarium.repo import Repo


pytestmark = pytest.mark.component


def test_builtin_runes_resolve_to_package_files(tmp_path):
    for name in ("deploy_access", "ci_access"):
        path = Path(resolve_rune(name, Repo(root=tmp_path)))
        assert path.is_absolute()
        assert path.is_file()
        assert path.stem == name


def test_repo_runes_resolve_to_absolute_paths_and_nullforge_names_pass_through(tmp_path):
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / "orrery.py").write_text('"""Orrery."""\n', encoding="utf-8")
    (tmp_path / "runes" / "_helpers.py").write_text("", encoding="utf-8")
    repo = Repo(root=tmp_path)
    assert resolve_rune("orrery", repo) == str((tmp_path / "runes" / "orrery.py").resolve())
    assert resolve_rune("telemt", repo) == "telemt"
    assert repo_runes(repo) == ["orrery"]


@pytest.mark.parametrize(
    "name",
    [
        "nosuchrune",
        "../etc/passwd",
        "runes/orrery.py",
    ],
)
def test_unknown_or_path_like_rune_names_are_refused(tmp_path, name):
    with pytest.raises(UsageProblem):
        resolve_rune(name, Repo(root=tmp_path))


def test_repo_rune_shadowing_a_builtin_is_invalid(tmp_path):
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / "deploy_access.py").write_text("", encoding="utf-8")
    with pytest.raises(InvalidManifest):
        repo_runes(Repo(root=tmp_path))


def test_repo_rune_shadowing_a_nullforge_rune_is_invalid(tmp_path):
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / "dns.py").write_text("", encoding="utf-8")
    with pytest.raises(InvalidManifest):
        resolve_rune("dns", Repo(root=tmp_path))


@pytest.mark.parametrize(
    "name",
    [
        "my-rune",
        "My_Rune",
        "9rune",
    ],
)
def test_repo_runes_rejects_bad_names(tmp_path, name):
    (tmp_path / "runes").mkdir()
    (tmp_path / "runes" / f"{name}.py").write_text("", encoding="utf-8")
    with pytest.raises(InvalidManifest):
        repo_runes(Repo(root=tmp_path))
