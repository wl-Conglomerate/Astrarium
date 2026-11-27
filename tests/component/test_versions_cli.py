"""`arium versions apply` CLI: confirmation, non-terminal guard, blank CI inputs."""

import json
from types import SimpleNamespace

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.components.inventory import component
from astrarium.components.inventory.controller import InventoryController
from astrarium.components.versions.component import VersionsComponent
from astrarium.errors import Declined, ExitCode, UsageProblem
from tests.support.deployment import fixture_app, make_deployment
from tests.support.fleet import FakeRunner


pytestmark = pytest.mark.component


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


def _terminal(monkeypatch, *, tty: bool) -> None:
    monkeypatch.setattr(
        component,
        "sys",
        SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: tty)),
    )


@pytest.fixture
def invoke(tmp_path, monkeypatch, runner):
    root = make_deployment(tmp_path / "repo", git=True)
    app = fixture_app(root)
    monkeypatch.setattr(
        InventoryController,
        "make_runner",
        lambda self: runner,
    )
    group = click.Group()
    VersionsComponent.expose_cli(group)

    def run(*args: str, answer: str | None = None):
        return CliRunner().invoke(
            group,
            [
                "versions",
                "apply",
                "telemt",
                *args,
            ],
            obj=app,
            input=answer,
        )

    return run


def test_declined_confirmation_exits_error(invoke, runner, monkeypatch) -> None:
    _terminal(monkeypatch, tty=True)

    result = invoke(answer="n\n")

    assert isinstance(result.exception, Declined)
    assert result.exception.exit_code is ExitCode.ERROR
    assert runner.calls == []


def test_confirmation_without_terminal_needs_yes(invoke, runner, monkeypatch) -> None:
    _terminal(monkeypatch, tty=False)

    result = invoke()

    assert isinstance(result.exception, UsageProblem)
    assert runner.calls == []


@pytest.mark.parametrize("blank", ["", " "])
def test_blank_limit_and_canary_mean_no_limit_and_no_canary(invoke, blank) -> None:
    result = invoke(
        "--yes",
        "--dry-run",
        "--json",
        "--limit",
        blank,
        "--canary",
        blank,
    )

    assert result.exception is None
    data = json.loads(result.stdout)["nodes"]
    assert {node_id for node_id, info in data.items() if info["status"] != "skipped"} == {"mskP00"}
