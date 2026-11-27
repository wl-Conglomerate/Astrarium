"""`arium fleet ssh`: runtime config scoped to target, argv, exit code passthrough, default identity."""

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import rich_click as click
from click.testing import CliRunner

from astrarium.components.sshcfg.component import SshComponent
from astrarium.components.sshcfg.controller import SshController
from astrarium.errors import UsageProblem
from tests.support.fake_transport import ScriptedNode
from tests.support.nodes import make_node
from tests.support.rollout_env import rollout_env


pytestmark = pytest.mark.component

FAKE_SSH = """#!{python}
import os, sys
open(os.environ["FAKE_SSH_ARGV"], "w").write("\\n".join(sys.argv[1:]))
sys.exit(7)
"""


def test_session_uses_target_scoped_config_and_returns_ssh_code(tmp_path, monkeypatch) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "ssh").write_text(FAKE_SSH.format(python=sys.executable))
    (bin_dir / "ssh").chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:/usr/bin:/bin")
    monkeypatch.setenv("FAKE_SSH_ARGV", str(tmp_path / "argv"))
    nodes = {
        "nlA00": make_node("nlA00"),
        "deA00": make_node(
            "deA00",
            ipv4="203.0.113.30",
            host_keys={},
        ),
    }
    env = rollout_env(
        tmp_path,
        nodes,
        {"nlA00": ScriptedNode()},
    )
    controller = SshController(env.controller.app)

    code = controller.session(
        "nlA00",
        ["uptime"],
        identity="deploy",
        via=None,
    )

    argv = (tmp_path / "argv").read_text().splitlines()
    options, target = argv[: argv.index("--")], argv[argv.index("--") + 1 :]
    assert code == 7
    assert options[0] == "-F" and not Path(options[1]).exists()
    assert options[options.index("BatchMode=no") - 1] == "-o"
    assert target == ["nlA00", "uptime"]
    with pytest.raises(UsageProblem):
        controller.session(
            "zz",
            [],
            identity="deploy",
            via=None,
        )


def test_cli_logs_in_as_deploy_user_by_default() -> None:
    calls = []

    def session(node, command, *, identity, via):
        calls.append(
            (
                node,
                command,
                identity,
                via,
            )
        )
        return 0

    group = click.Group()
    SshComponent.expose_cli(group)
    result = CliRunner().invoke(
        group,
        [
            "fleet",
            "ssh",
            "nlA00",
            "id",
            "-un",
        ],
        obj=SimpleNamespace(sshcfg=SimpleNamespace(session=session)),
    )

    assert result.exit_code == 0
    assert calls == [
        (
            "nlA00",
            ["id", "-un"],
            "deploy",
            None,
        )
    ]
