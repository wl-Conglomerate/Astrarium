"""changed_since against real git history."""

import pytest

from astrarium.components.versions.changes import changed_since
from astrarium.errors import Refused
from astrarium.repo import Repo
from tests.support.deployment import git


pytestmark = pytest.mark.component

MANIFEST = """\
deployment: {{name: test, domain: example.net}}
versions: {{telemt: {telemt}}}
nodes:
  plsA00: {{role: pulsar, ipv4: 203.0.113.40}}
"""

LOCK = """\
version = 1

[[package]]
name = "nullforge"
version = "{version}"
source = {{ registry = "https://photon.example.net/simple/" }}
"""


def _commit(root, *, telemt, nullforge="0.3.1"):
    (root / "astrarium.yaml").write_text(MANIFEST.format(telemt=telemt), encoding="utf-8")
    (root / "uv.lock").write_text(LOCK.format(version=nullforge), encoding="utf-8")
    git(
        root,
        "add",
        "-A",
    )
    git(
        root,
        "commit",
        "-q",
        "-m",
        f"pin telemt {telemt}",
    )
    return git(
        root,
        "rev-parse",
        "HEAD",
    )


@pytest.fixture
def history(tmp_path):
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    return tmp_path


def test_changes_since_base_commit_cover_changed_pins(history):
    base = _commit(history, telemt="3.5.6")
    _commit(history, telemt="3.5.7")
    changes = changed_since(Repo(root=history), base)
    assert changes.base == base
    assert changes.by_node == {"plsA00": ["telemt"]}


def test_unknown_base_or_nullforge_bump_is_refused(history):
    base = _commit(history, telemt="3.5.6")
    _commit(
        history,
        telemt="3.5.6",
        nullforge="0.4.0",
    )
    with pytest.raises(Refused):
        changed_since(Repo(root=history), "f" * 40)
    with pytest.raises(Refused):
        changed_since(Repo(root=history), base)


def test_changes_since_works_when_repo_root_is_nested_in_a_bigger_worktree(tmp_path):
    git(
        tmp_path,
        "init",
        "-q",
        "-b",
        "main",
    )
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    base = _commit(deploy, telemt="3.5.6")
    _commit(deploy, telemt="3.5.7")
    changes = changed_since(Repo(root=deploy), base)
    assert changes.base == base
    assert changes.by_node == {"plsA00": ["telemt"]}
