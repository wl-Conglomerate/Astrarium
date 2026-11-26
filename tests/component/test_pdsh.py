"""`arium fleet pdsh`: CLI surface, exit codes, JSON, collapse, and controller run over fake transport."""

import asyncio
import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.components.pdsh.component import PdshComponent
from astrarium.components.pdsh.controller import NodeResult, PdshController, PdshOptions, PdshReport
from astrarium.components.rollout.transport import CommandResult
from astrarium.errors import UsageProblem
from tests.support.fake_transport import FakeTransport, ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import rollout_env


pytestmark = pytest.mark.component


def report(*results: NodeResult) -> PdshReport:
    return PdshReport(
        command="uptime",
        via="direct",
        targets=[r.node_id for r in results],
        skipped={},
        results=list(results),
    )


@pytest.fixture
def invoke():
    group = click.Group()
    PdshComponent.expose_cli(group)

    def run(*args: str, results: list[NodeResult] | None = None) -> tuple[Any, list[str]]:
        seen: list[str] = []

        async def fake_run(command: str, opts: object) -> PdshReport:
            seen.append(command)
            return report(*(results or []))

        stub = SimpleNamespace(run=fake_run)
        result = CliRunner().invoke(group, ["fleet", "pdsh", *args], obj=SimpleNamespace(pdsh=stub))
        return result, seen

    return run


async def _coro(value: Any) -> Any:
    return value


def test_no_command_is_usage_error(invoke) -> None:
    result, _ = invoke()
    assert isinstance(result.exception, UsageProblem)


def test_all_ok_exits_zero_and_prefixes_lines(invoke) -> None:
    result, _ = invoke("uptime", results=[NodeResult("nlA00", 0, "load 0.1\n", "")])
    assert result.exit_code == 0, result.output
    assert "nlA00: load 0.1" in result.output


def test_failed_nodes_set_exit_code_to_failure_count(invoke) -> None:
    results = [NodeResult("nlA00", 0, "", ""), NodeResult("mskA00", 1, "", "boom\n"), NodeResult("nlA20", 3, "", "")]
    result, _ = invoke("--json", "uptime", results=results)
    assert result.exit_code == 2, result.output
    data = json.loads(result.output)
    assert [item["rc"] for item in data["results"]] == [0, 1, 3]
    assert data["command"] == "uptime"


def test_collapse_groups_identical_output_in_json(invoke) -> None:
    results = [
        NodeResult("nlA00", 0, "same\n", ""),
        NodeResult("nlA20", 0, "same\n", ""),
        NodeResult("mskA00", 1, "", "no\n"),
    ]
    result, _ = invoke("--json", "--collapse", "uptime", results=results)
    assert result.exit_code == 1
    groups = json.loads(result.output)["groups"]
    assert [(g["nodes"], g["rc"], g["stdout"]) for g in groups] == [
        (["nlA00", "nlA20"], 0, "same\n"),
        (["mskA00"], 1, ""),
    ]


def test_single_quoted_command_passes_through_unquoted(invoke) -> None:
    # pdsh semantics: one quoted 'cmd args' string is parsed by the remote shell, not re-quoted
    result, seen = invoke("curl -sq6 --interface warp ifconfig.co", results=[NodeResult("nlA00", 0, "x\n", "")])
    assert result.exit_code == 0
    assert seen == ["curl -sq6 --interface warp ifconfig.co"]


def test_multiple_command_args_join_with_spaces(invoke) -> None:
    result, seen = invoke("curl", "-sq6", "ifconfig.co", results=[NodeResult("nlA00", 0, "x\n", "")])
    assert seen == ["curl -sq6 ifconfig.co"]


def test_failed_nodes_get_detail_block(invoke) -> None:
    results = [NodeResult("nlA00", 0, "ok\n", ""), NodeResult("mskZ00", 1, "", "curl: (7) no warp iface\n")]
    result, _ = invoke("curl -sq6 --interface warp ifconfig.co", results=results)
    assert result.exit_code == 1
    assert "mskZ00" in result.output and "rc=1" in result.output
    assert "no warp iface" in result.output


def test_collapse_header_shows_rc_for_failed_group(invoke) -> None:
    results = [NodeResult("nlA00", 1, "", "boom\n"), NodeResult("nlA20", 1, "", "boom\n")]
    result, _ = invoke("--collapse", "true", results=results)
    assert result.exit_code == 2
    assert "nlA00,nlA20 (rc=1)" in result.output


def test_collapse_coalesces_identical_output_into_one_block(invoke) -> None:
    results = [
        NodeResult("nlA00", 0, "ok\n", ""),
        NodeResult("nlA20", 0, "ok\n", ""),
        NodeResult("mskA00", 0, "x\n", ""),
    ]
    result, _ = invoke("--collapse", "echo ok", results=results)
    assert result.exit_code == 0
    assert "----------------\nnlA00,nlA20\n----------------\nok" in result.output
    assert "----------------\nmskA00\n----------------\nx" in result.output


def test_blocks_renders_one_block_per_node(invoke) -> None:
    results = [NodeResult("nlA00", 0, "load 0.1\n", ""), NodeResult("nlA20", 0, "load 0.2\n", "")]
    result, _ = invoke("--blocks", "uptime", results=results)
    assert result.exit_code == 0
    assert "----------------\nnlA00\n----------------\nload 0.1" in result.output
    assert "----------------\nnlA20\n----------------\nload 0.2" in result.output
    assert "nlA00: load 0.1" not in result.output


def test_collapse_and_blocks_are_mutually_exclusive(invoke) -> None:
    result, _ = invoke("--collapse", "--blocks", "true", results=[])
    assert isinstance(result.exception, UsageProblem)


def test_dry_run_lists_targets_without_results(invoke) -> None:
    result, _ = invoke("--dry-run", "--json", "uptime", results=[])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["results"] == []
    assert data["command"] == "uptime"


class AnyCommandTransport(FakeTransport):
    """Answers any pdsh command: rc 0 with node echo, 255 when unreachable."""

    async def run(self, node_id: str, command: str, *, stdin: bytes | None = None, timeout: float | None = None):
        self._require_scope(node_id)
        self.calls.append((node_id, command))
        if self.nodes[node_id].unreachable:
            return CommandResult(255, "", "unreachable")
        return CommandResult(0, f"{node_id}: ran {command}\n", "")


def test_controller_runs_command_on_selected_nodes(tmp_path, monkeypatch) -> None:
    nodes = {"nlA00": make_node("nlA00"), "mskA10": make_node("mskA10", role="hub"), "nlA20": make_node("nlA20")}
    fakes = {"nlA00": ScriptedNode(), "mskA10": ScriptedNode(), "nlA20": ScriptedNode(unreachable=True)}
    env = rollout_env(tmp_path, nodes, fakes)
    controller = PdshController(cast(Any, env.controller.app))
    transport = AnyCommandTransport(fakes)
    controller.make_transport = lambda paths, jumped: transport

    rep = asyncio.run(controller.run("uptime", PdshOptions(limit="@exit", identity="deploy", via=None)))

    assert rep.command == "uptime"
    assert rep.targets == ["nlA00", "nlA20"]
    assert [r.node_id for r in rep.results] == ["nlA00", "nlA20"]
    assert rep.results[0].rc == 0 and "ran uptime" in rep.results[0].stdout
    assert rep.results[1].rc == 255
    assert all(command == "uptime" for _, command in transport.calls)


def test_controller_dry_run_needs_no_transport(tmp_path) -> None:
    nodes = {"nlA00": make_node("nlA00")}
    env = rollout_env(tmp_path, nodes, {"nlA00": ScriptedNode()})
    controller = PdshController(cast(Any, env.controller.app))
    controller.make_transport = lambda paths, jumped: (_ for _ in ()).throw(AssertionError("no transport"))

    rep = asyncio.run(controller.run("uptime", PdshOptions(limit=None, identity="deploy", via=None, dry_run=True)))

    assert rep.results == []
    assert rep.targets == ["nlA00"]
