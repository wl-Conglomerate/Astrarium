"""`arium fleet deploy` command: exit codes, CI inputs, JSON output."""

import json
from types import SimpleNamespace

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.components.rollout import component, transport
from astrarium.components.rollout.component import RolloutComponent
from astrarium.errors import Declined, ExitCode, PartialFailure
from tests.support.fake_transport import ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import rollout_env


pytestmark = pytest.mark.component


@pytest.fixture
def terminal(monkeypatch) -> None:
    monkeypatch.setattr(
        component,
        "sys",
        SimpleNamespace(stdin=SimpleNamespace(isatty=lambda: True)),
    )


@pytest.fixture
def invoke(tmp_path, monkeypatch):
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setattr(
        transport,
        "RETRY_DELAY",
        0.0,
    )
    nodes = {"nlA00": make_node("nlA00"), "mskA10": make_node("mskA10", role="hub")}
    env = rollout_env(
        tmp_path,
        nodes,
        {"nlA00": ScriptedNode(verdicts=["rolled_back"]), "mskA10": ScriptedNode()},
    )
    group = click.Group()
    RolloutComponent.expose_cli(group)

    def run(*args: str, answer: str | None = None):
        return CliRunner().invoke(
            group,
            [
                "fleet",
                "deploy",
                *args,
            ],
            obj=SimpleNamespace(rollout=env.controller),
            input=answer,
        )

    return run


def test_failed_node_exits_partial(invoke) -> None:
    result = invoke("--yes")

    assert isinstance(result.exception, PartialFailure)


@pytest.mark.parametrize("blank", ["", " "])
def test_blank_ci_inputs_mean_no_limit_and_no_canary(invoke, blank) -> None:
    result = invoke(
        "--yes",
        "--json",
        "--limit",
        blank,
        "--canary",
        blank,
    )

    assert {item["node"] for item in json.loads(result.output)["outcomes"]} == {"nlA00", "mskA10"}


def test_json_output_lists_outcomes(invoke) -> None:
    result = invoke("--yes", "--json")

    data = json.loads(result.output)
    assert {item["node"]: item["status"] for item in data["outcomes"]} == {"nlA00": "failed", "mskA10": "ok"}


def test_declined_confirmation_exits_error(invoke, terminal) -> None:
    result = invoke(answer="n\n")

    assert isinstance(result.exception, Declined)
    assert result.exception.exit_code is ExitCode.ERROR


def test_json_confirmation_shows_plan_on_stderr(invoke, terminal) -> None:
    result = invoke("--json", answer="n\n")

    assert "nlA00" in result.stderr
