"""`arium fleet provision` CLI: confirmation, non-terminal guard, blank CI inputs, JSON output."""

import json
from types import SimpleNamespace

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.components.inventory import component
from astrarium.components.inventory.cast import CastResult
from astrarium.components.inventory.component import InventoryComponent
from astrarium.components.inventory.controller import InventoryController
from astrarium.errors import Declined, ExitCode, PartialFailure, UsageProblem
from tests.support.deployment import fixture_app, make_deployment
from tests.support.fleet import FakeRunner


pytestmark = pytest.mark.component

NON_BASTION_NODES = {
    "nlA00",
    "mskA00",
    "mskP00",
}


@pytest.fixture
def runner() -> FakeRunner:
    return FakeRunner()


@pytest.fixture
def terminal(monkeypatch) -> None:
    monkeypatch.setattr(
        component,
        "sys",
        SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)),
    )


@pytest.fixture
def no_terminal(monkeypatch) -> None:
    monkeypatch.setattr(
        component,
        "sys",
        SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: False)),
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
    InventoryComponent.expose_cli(group)

    def run(*args: str, answer: str | None = None):
        return CliRunner().invoke(
            group,
            [
                "fleet",
                "provision",
                *args,
            ],
            obj=app,
            input=answer,
        )

    return run


def test_declined_confirmation_exits_error(invoke, terminal) -> None:
    result = invoke(answer="n\n")

    assert isinstance(result.exception, Declined)
    assert result.exception.exit_code is ExitCode.ERROR


def test_confirmation_without_terminal_needs_yes(invoke, no_terminal) -> None:
    result = invoke()

    assert isinstance(result.exception, UsageProblem)


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

    data = json.loads(result.stdout)["nodes"]
    assert data["edge"]["status"] == "skipped"  # bastion, not named in --limit
    cast_nodes = {node_id for node_id, info in data.items() if info["status"] != "skipped"}
    assert cast_nodes == NON_BASTION_NODES


def test_json_output_with_yes_parses_while_preview_goes_to_stderr(invoke) -> None:
    result = invoke(
        "--yes",
        "--dry-run",
        "--json",
    )

    data = json.loads(result.stdout)
    assert set(data["nodes"]) == NON_BASTION_NODES | {"edge"}
    assert "provision" in result.stderr


@pytest.mark.parametrize("blank", ["", " "])
def test_blank_rune_means_full_provision(invoke, blank) -> None:
    result = invoke(
        "--yes",
        "--dry-run",
        "--json",
        "--rune",
        blank,
    )

    assert result.exception is None
    data = json.loads(result.stdout)["nodes"]
    assert set(data) == NON_BASTION_NODES | {"edge"}


def test_failed_cast_exits_partial_failure(invoke, runner) -> None:
    runner.script = lambda limits, runes: CastResult(1, list(limits), {}, 1)

    result = invoke("--yes", "--dry-run")

    assert isinstance(result.exception, PartialFailure)
    assert result.exception.exit_code is ExitCode.PARTIAL
