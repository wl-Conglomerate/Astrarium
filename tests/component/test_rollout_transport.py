"""OpenSSH transport against fake ssh and scp binaries."""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import ControlSection
from astrarium.components.rollout.transport import OpenSshTransport, open_deploy_transport, write_scoped_ssh
from astrarium.components.sshcfg.render import SshPaths
from astrarium.errors import InvalidManifest
from astrarium.runtime import RuntimeDir
from tests.support.fake_transport import FakeTransport
from tests.support.nodes import make_node


pytestmark = pytest.mark.component

FAKE_SSH = """#!{python}
import json, os, sys, time
log = os.environ["FAKE_SSH_LOG"]
node = sys.argv[3]
with open(log, "a") as handle:
    handle.write(json.dumps({{"argv": sys.argv[1:], "node": node, "event": 1, "t": time.time()}}) + "\\n")
time.sleep(float(os.environ.get("FAKE_SSH_SLEEP", "0")))
with open(log, "a") as handle:
    handle.write(json.dumps({{"node": node, "event": -1, "t": time.time()}}) + "\\n")
sys.exit(int(os.environ.get("FAKE_SSH_RC", "0")))
"""

FAKE_SCP = """#!{python}
import os, shutil, sys
*sources, target = [a for a in sys.argv[1:] if a not in ("-q",)][2:]
remote = os.environ["FAKE_REMOTE"] + target.split(":", 1)[1]
os.makedirs(remote, exist_ok=True)
for source in sources:
    shutil.copy(source, remote)
"""

CONTROL = ControlSection(deploy_user="github_actions", jump="edge")


def fleet() -> dict[str, EffectiveNode]:
    return {
        "edge": make_node(
            "edge",
            role="bastion",
            ipv4="198.51.100.20",
        ),
        "nlA00": make_node("nlA00", ipv4="203.0.113.10"),
        "mskA10": make_node(
            "mskA10",
            role="hub",
            ipv4="203.0.113.20",
        ),
    }


@pytest.fixture
def fake_bin(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("ssh", FAKE_SSH), ("scp", FAKE_SCP)):
        path = bin_dir / name
        path.write_text(body.format(python=sys.executable))
        path.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{Path('/usr/bin')}:{Path('/bin')}")
    monkeypatch.setenv("FAKE_SSH_LOG", str(tmp_path / "ssh.log"))
    monkeypatch.setenv("FAKE_REMOTE", str(tmp_path / "remote"))
    return tmp_path


def paths_in(tmp_path: Path, *nodes: str) -> SshPaths:
    config = tmp_path / "ssh_config"
    config.write_text("")
    scope = frozenset(nodes or ("nlA00",))
    return SshPaths(
        config=config,
        known_hosts=tmp_path / "known_hosts",
        identity="deploy",
        via="jump",
        nodes=scope,
    )


def max_parallel(log: Path) -> int:
    entries = [json.loads(line) for line in log.read_text().splitlines()]
    running = peak = 0
    for entry in sorted(entries, key=lambda e: (e["t"], e["event"])):
        running += entry["event"]
        peak = max(peak, running)
    return peak


def test_run_uses_generated_config_and_node_alias(fake_bin) -> None:
    transport = OpenSshTransport(paths_in(fake_bin), jumped=frozenset())

    result = asyncio.run(transport.run("nlA00", "true"))

    entry = json.loads((fake_bin / "ssh.log").read_text().splitlines()[0])
    assert result.rc == 0
    assert entry["argv"] == [
        "-F",
        str(fake_bin / "ssh_config"),
        "nlA00",
        "true",
    ]


def test_jumped_connections_are_capped(fake_bin, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_SSH_SLEEP", "0.3")
    jumped = {f"j{i}" for i in range(6)}
    transport = OpenSshTransport(
        paths_in(fake_bin, *jumped),
        jumped=frozenset(jumped),
        jump_limit=2,
    )

    async def everything() -> None:
        await asyncio.gather(*(transport.run(node, "true") for node in sorted(jumped)))

    asyncio.run(everything())

    assert max_parallel(fake_bin / "ssh.log") <= 2


def test_timeout_counts_as_transport_failure(fake_bin, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_SSH_SLEEP", "5")
    transport = OpenSshTransport(paths_in(fake_bin), jumped=frozenset())

    assert (
        asyncio.run(
            transport.run(
                "nlA00",
                "true",
                timeout=0.2,
            )
        ).rc
        == 255
    )


def test_upload_places_files_under_mapping_names(fake_bin) -> None:
    source = fake_bin / "rendered.json"
    source.write_text("{}")
    transport = OpenSshTransport(paths_in(fake_bin), jumped=frozenset())

    result = asyncio.run(
        transport.upload(
            "nlA00",
            {"config.json": source},
            "/stage",
        )
    )

    assert result.rc == 0
    assert (fake_bin / "remote" / "stage" / "config.json").read_text() == "{}"


def test_upload_falls_back_to_copy_when_hardlink_fails_and_keeps_mode(fake_bin, monkeypatch) -> None:
    """os.link raising OSError forces copyfile fallback, source mode must still land on target."""

    source = fake_bin / "xray"
    source.write_text("binary")
    source.chmod(0o750)
    monkeypatch.setattr(
        os,
        "link",
        lambda *_a, **_k: (_ for _ in ()).throw(OSError("cross-device link")),
    )
    transport = OpenSshTransport(paths_in(fake_bin), jumped=frozenset())

    result = asyncio.run(
        transport.upload(
            "nlA00",
            {"xray": source},
            "/stage",
        )
    )

    assert result.rc == 0
    assert (fake_bin / "remote" / "stage" / "xray").stat().st_mode & 0o777 == 0o750


def test_node_outside_generated_config_is_refused(fake_bin) -> None:
    source = fake_bin / "rendered.json"
    source.write_text("{}")
    transport = OpenSshTransport(paths_in(fake_bin, "nlA00"), jumped=frozenset())

    with pytest.raises(ValueError):
        asyncio.run(transport.run("mskA10", "true"))
    with pytest.raises(ValueError):
        asyncio.run(
            transport.upload(
                "mskA10",
                {"config.json": source},
                "/stage",
            )
        )
    assert not (fake_bin / "ssh.log").exists()
    assert not (fake_bin / "remote").exists()


@pytest.mark.parametrize(("via", "scope"), [("jump", {"nlA00", "edge"}), ("direct", {"nlA00"})])
def test_deploy_transport_covers_wanted_nodes_and_jump_only(via, scope) -> None:
    made: list[tuple[SshPaths, frozenset[str]]] = []

    def make(paths: SshPaths, jumped: frozenset[str]) -> FakeTransport:
        made.append((paths, jumped))
        return FakeTransport({})

    with RuntimeDir() as runtime:
        open_deploy_transport(
            runtime,
            fleet(),
            CONTROL,
            via,
            make,
            wanted=["nlA00"],
        )

    [(paths, jumped)] = made
    assert paths.nodes == scope
    assert jumped == (scope if via == "jump" else set())


def test_write_scoped_ssh_matches_the_scope_open_deploy_transport_passes_on() -> None:
    with RuntimeDir() as runtime:
        paths, jumped = write_scoped_ssh(
            runtime,
            fleet(),
            CONTROL,
            "deploy",
            "jump",
            wanted=["nlA00"],
        )

    assert paths.identity == "deploy"
    assert paths.via == "jump"
    assert paths.nodes == {"nlA00", "edge"}
    assert jumped == {"nlA00", "edge"}


def test_keyless_node_blocks_ssh_files_only_when_wanted() -> None:
    nodes = {
        **fleet(),
        "deA00": make_node(
            "deA00",
            ipv4="203.0.113.30",
            host_keys={},
        ),
    }

    def make(paths: SshPaths, jumped: frozenset[str]) -> FakeTransport:
        return FakeTransport({})

    with RuntimeDir() as runtime:
        open_deploy_transport(
            runtime,
            nodes,
            CONTROL,
            "jump",
            make,
            wanted=["nlA00"],
        )
        with pytest.raises(InvalidManifest):
            open_deploy_transport(
                runtime,
                nodes,
                CONTROL,
                "jump",
                make,
                wanted=["deA00"],
            )
