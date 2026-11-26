"""xray HEAD build list for CI matrices."""

from __future__ import annotations

import json
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.app import AstrariumApp
from astrarium.components.check.component import CheckComponent
from astrarium.errors import Refused, UsageProblem
from tests.support.check_repo import XRAY_SHA, make_check_repo, manifest_data


pytestmark = pytest.mark.component


class StubUpstream:
    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool:
        return self.reachable

    def __init__(self, reachable: bool) -> None:
        self.reachable = reachable


def _app(tmp_path: Path, **node_updates: dict[str, Any]) -> AstrariumApp:
    manifest = manifest_data()
    for node_id, update in node_updates.items():
        manifest["nodes"][node_id].update(update)
    return AstrariumApp(make_check_repo(tmp_path / "repo", manifest=manifest))


def test_deploy_builds_every_node_arch_and_check_only_runner_arch(tmp_path: Path) -> None:
    app = _app(tmp_path, nlA00={"arch": "aarch64"})

    deploy = {
        (
            b.sha,
            b.arch,
            b.goarch,
        )
        for b in app.check.xray_builds(
            "deploy",
            "x86_64",
            upstream=StubUpstream(True),
        )
    }
    check = {
        (b.sha, b.arch)
        for b in app.check.xray_builds(
            "check",
            "x86_64",
            upstream=StubUpstream(True),
        )
    }

    assert deploy == {
        (
            XRAY_SHA,
            "x86_64",
            "amd64",
        ),
        (
            XRAY_SHA,
            "aarch64",
            "arm64",
        ),
    }
    assert check == {(XRAY_SHA, "x86_64")}


def test_two_main_pins_for_one_arch_are_refused(tmp_path: Path) -> None:
    app = _app(tmp_path, nlA00={"overrides": {"versions": {"xray": "main@" + "f" * 40}}})

    with pytest.raises(UsageProblem):
        app.check.xray_builds(
            "deploy",
            "x86_64",
            upstream=StubUpstream(True),
        )


def test_commit_off_upstream_main_is_refused(tmp_path: Path) -> None:
    app = _app(tmp_path)

    with pytest.raises(Refused):
        app.check.xray_builds(
            "deploy",
            "x86_64",
            upstream=StubUpstream(False),
        )


def test_cli_json_is_workflow_matrix_and_empty_list_without_main_pins(tmp_path: Path) -> None:
    group = click.Group()
    CheckComponent.expose_cli(group)
    release = manifest_data()
    release["versions"]["xray"] = {"version": "v26.9.9", "sha256": {"x86_64": "0" * 64}}
    head_app = _app(tmp_path / "head")
    release_app = AstrariumApp(make_check_repo(tmp_path / "release" / "repo", manifest=release))

    def matrix(app: AstrariumApp) -> Any:
        check = SimpleNamespace(xray_builds=partial(app.check.xray_builds, upstream=StubUpstream(True)))
        argv = [
            "ci",
            "xray-builds",
            "--for",
            "deploy",
            "--runner-arch",
            "x86_64",
            "--json",
        ]
        result = CliRunner().invoke(
            group,
            argv,
            obj=SimpleNamespace(check=check),
        )
        assert result.exit_code == 0, result.output
        return json.loads(result.output)

    assert matrix(head_app) == [
        {
            "sha": XRAY_SHA,
            "arch": "x86_64",
            "goarch": "amd64",
        }
    ]
    assert matrix(release_app) == []
