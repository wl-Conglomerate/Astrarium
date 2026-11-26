"""Generated SSH files as paramiko and OpenSSH read them."""

import shutil
import stat
import subprocess

import paramiko
import pytest

from astrarium.components.manifest.models import ControlSection
from astrarium.components.sshcfg.render import write_ssh_files
from astrarium.runtime import RuntimeDir
from tests.support.nodes import make_node


pytestmark = pytest.mark.component

CONTROL = ControlSection(deploy_user="github_actions", jump="edge")


@pytest.fixture
def fleet():
    return {
        "edge": make_node(
            "edge",
            role="bastion",
            ipv4="198.51.100.20",
            ssh_port=22443,
            ssh_user="keeper",
        ),
        "nlA00": make_node(
            "nlA00",
            ipv4="203.0.113.10",
            fqdn="nlA00.aphelion.example.net",
        ),
    }


def test_known_hosts_loads_in_paramiko_by_resolved_hostname(fleet) -> None:
    with RuntimeDir() as runtime:
        paths = write_ssh_files(
            runtime,
            fleet,
            CONTROL,
            "deploy",
            "jump",
        )
        loaded = paramiko.HostKeys(str(paths.known_hosts))

        assert loaded.lookup("203.0.113.10") is not None
        assert loaded.lookup("nla00.aphelion.example.net") is not None
        assert loaded.lookup("[198.51.100.20]:22443") is not None
        assert loaded.lookup("198.51.100.20") is None
        assert stat.S_IMODE(paths.known_hosts.stat().st_mode) == 0o600


def test_identities_and_routes_get_separate_files(fleet) -> None:
    with RuntimeDir() as runtime:
        deploy = write_ssh_files(
            runtime,
            fleet,
            CONTROL,
            "deploy",
            "jump",
        )
        before = deploy.config.read_text()
        admin = write_ssh_files(
            runtime,
            fleet,
            CONTROL,
            "admin",
            "direct",
        )

        assert admin.config != deploy.config
        assert deploy.config.read_text() == before
        assert str(deploy.known_hosts) in before


@pytest.mark.skipif(shutil.which("ssh") is None, reason="needs OpenSSH client")
def test_ssh_resolves_generated_config(fleet) -> None:
    with RuntimeDir() as runtime:
        paths = write_ssh_files(
            runtime,
            fleet,
            CONTROL,
            "deploy",
            "jump",
        )

        def resolved(host: str) -> dict[str, str]:
            argv = [
                "ssh",
                "-G",
                "-F",
                str(paths.config),
                host,
            ]
            out = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=True,
            )
            return dict(line.split(" ", 1) for line in out.stdout.splitlines() if " " in line)

        node = resolved("nlA00")
        hop = resolved("edge")

    assert node["hostname"] == "203.0.113.10"
    assert node["user"] == "github_actions"
    assert node["proxyjump"] == "edge"
    assert node["stricthostkeychecking"] == "true"
    assert node["userknownhostsfile"] == str(paths.known_hosts)
    assert (hop["port"], hop["user"]) == ("22443", "github_actions")
