"""NullForge cast, then deploy, through CLI against disposable target (mock evidence, never production)."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from astrarium.components.topology.bridge import NAMESPACE_PLACEHOLDER
from tests.support.deployment import git_commit_all
from tests.support.it_target import ItTarget
from tests.support.template import template_copy


pytestmark = pytest.mark.integration

ARIUM = Path(sys.executable).with_name("arium")

NODE = "itA00"

DOMAIN = "example.net"

DEPLOY_USER = "github_actions"

XRAY_CONFIG = "/usr/local/etc/xray/config.json"

CAST_TIMEOUT = 1800.0

DEPLOY_TIMEOUT = 900.0

SOPS_IDENTITIES = (
    "SOPS_AGE_KEY",
    "SOPS_AGE_KEY_FILE",
    "SOPS_AGE_KEY_CMD",
)

"""Operator identities left out: only harness key decrypts, no keychain prompt."""

TOPOLOGY = f"""\
global:
  namespace: {NAMESPACE_PLACEHOLDER}
  aphelion_domain: aphelion.{DOMAIN}

defaults:
  exit:
    ipv6: false
    haproxy: false
    keys:
      auth: x25519
      mode: native
      session_time: 600s
  hub:
    ipv6: false
    keys:
      auth: x25519
      mode: native
      session_time: 600s
    exit_connections:
      method: mlkem768x25519plus
      fingerprint: chrome
    reality:
      dest: www.example.net:443

groups: []
users: []

routing:
  hub_default: direct

regions:
  - id: it
    type: exit
    vless_route: 1000
    nodes:
      - id: {NODE}
        hostname: {NODE}.aphelion.{DOMAIN}
        reality:
          dest: www.example.net:443
        xhttp:
          path: /update/
"""

EXIT_FEATURES: dict[str, Any] = {
    "xray": {"install": True},
    "haproxy": {"install": False},
    "warp": {"install": False},
    "dns": {"mode": "none"},
    "netsec": {"install": False},
    "users": {"users": []},
    "profiles": {"for_root": False},
    "monitoring": {"install": False},
}

"""Exit deltas: xray on, HAProxy off (topology disables it), no UFW, DNS or admin-user changes on shared target."""


def _arium(env: Mapping[str, str], *args: str, timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(ARIUM), *args],
        env=dict(env),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _manifest(target: ItTarget, public_key: str) -> dict[str, Any]:
    return {
        "deployment": {
            "name": "it",
            "domain": DOMAIN,
            "names": {
                "exit": "aphelion",
                "hub": "perigee",
                "pulsar": "pulsar",
            },
        },
        "control": {"deploy_user": DEPLOY_USER, "deploy_keys": [public_key]},
        "roles": {"exit": {"features": EXIT_FEATURES}},
        "nodes": {
            NODE: {
                "role": "exit",
                "ipv4": target.host,
                "arch": target.arch(),
                "ssh": {"port": target.port, "user": target.user},
                "host_keys": {"ed25519": target.host_key},
            }
        },
    }


def _live_config_sha(target: ItTarget) -> str:
    return target.run(f"sha256sum {XRAY_CONFIG}").stdout.split()[0]


@pytest.fixture(scope="module")
def first_deploy(e2e: E2eRepo) -> subprocess.CompletedProcess[str]:
    return e2e.arium(
        "fleet",
        "deploy",
        "--limit",
        NODE,
        "--via",
        "direct",
        "--yes",
    )


@dataclass(frozen=True)
class E2eRepo:
    """Deployment repo from `arium repo init`, environment of every `arium` call, xray pin."""

    root: Path
    env: dict[str, str]
    pin: str

    def arium(self, *args: str, timeout: float = DEPLOY_TIMEOUT) -> subprocess.CompletedProcess[str]:
        return _arium(
            self.env,
            "--repo",
            str(self.root),
            *args,
            timeout=timeout,
        )


def _ok(proc: subprocess.CompletedProcess[str]) -> subprocess.CompletedProcess[str]:
    assert proc.returncode == 0, f"{proc.args!r} exited {proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return proc


def _xray_state(target: ItTarget) -> tuple[str, str]:
    """(is-active, ActiveEnterTimestampMonotonic) of xray unit."""

    active = target.run("systemctl is-active xray", check=False).stdout.strip()
    since = target.run("systemctl show -p ActiveEnterTimestampMonotonic --value xray").stdout.strip()
    return active, since


@pytest.fixture(scope="module")
def e2e(it_target: ItTarget, it_agent: Mapping[str, str], tmp_path_factory: pytest.TempPathFactory) -> E2eRepo:
    """Repo from `arium repo init` with real sops, node cast with xray and deploy_access, xray pinned and committed."""

    if shutil.which("sops") is None:
        pytest.fail("sops not on PATH: e2e encrypts overlay and key files with real sops", pytrace=False)
    work = tmp_path_factory.mktemp("e2e")
    env = {name: value for name, value in os.environ.items() if name not in SOPS_IDENTITIES}
    env.update(it_agent)
    env["SOPS_AGE_SSH_PRIVATE_KEY_FILE"] = str(it_target.key)
    public_key = it_target.public_key()
    root = work / "deployment"
    _ok(
        _arium(
            env,
            "repo",
            "init",
            str(root),
            "--name",
            "it",
            "--domain",
            DOMAIN,
            "--photon-url",
            "https://photon.example.net/simple/",
            "--recipient",
            public_key,
            "--no-dns",
            "--template",
            str(template_copy(work / "template")),
            "--defaults",
            "--skip-lock",
            timeout=DEPLOY_TIMEOUT,
        )
    )
    (root / "astrarium.yaml").write_text(yaml.safe_dump(_manifest(it_target, public_key), sort_keys=False))
    (root / "topology.yaml").write_text(TOPOLOGY)
    repo = E2eRepo(
        root=root,
        env=env,
        pin="",
    )
    _ok(
        repo.arium(
            "keys",
            "gen",
            NODE,
        )
    )
    git_commit_all(root, "integration deployment")
    _ok(
        repo.arium(
            "fleet",
            "provision",
            "--limit",
            NODE,
            "--rune",
            "deploy_access",
            "--rune",
            "xray",
            "--via",
            "direct",
            "--yes",
            timeout=CAST_TIMEOUT,
        )
    )
    installed = it_target.run("/usr/local/bin/xray version").stdout.split()[1]
    pin = os.environ.get("ASTRARIUM_IT_XRAY_TAG", f"v{installed}")
    _ok(
        repo.arium(
            "versions",
            "bump",
            "xray",
            pin,
        )
    )
    git_commit_all(root, f"pin xray {pin}")
    # reused target keeps deploy state of earlier runs: recorded commit unknown here fails node (exit 3)
    it_target.sudo(f"rm -rf /home/{DEPLOY_USER}/.astrarium")
    return E2eRepo(
        root=root,
        env=env,
        pin=pin,
    )


def test_first_deploy_installs_rendered_config_and_pinned_xray(
    e2e: E2eRepo,
    first_deploy: subprocess.CompletedProcess[str],
    it_target: ItTarget,
    tmp_path: Path,
) -> None:
    _ok(first_deploy)
    out = tmp_path / "build"

    _ok(
        e2e.arium(
            "fleet",
            "build",
            "--limit",
            NODE,
            "--out",
            str(out),
        )
    )

    [built] = sorted(out.rglob("config.json"))
    assert _live_config_sha(it_target) == hashlib.sha256(built.read_bytes()).hexdigest()
    assert it_target.run("/usr/local/bin/xray version").stdout.split()[1] == e2e.pin.removeprefix("v")
    assert _xray_state(it_target)[0] == "active"


def test_repeat_deploy_leaves_node_untouched(
    e2e: E2eRepo,
    first_deploy: subprocess.CompletedProcess[str],
    it_target: ItTarget,
) -> None:
    _ok(first_deploy)
    before = _xray_state(it_target)
    config = _live_config_sha(it_target)

    _ok(
        e2e.arium(
            "fleet",
            "deploy",
            "--limit",
            NODE,
            "--via",
            "direct",
            "--yes",
        )
    )

    assert before[0] == "active"
    assert _xray_state(it_target) == before
    assert _live_config_sha(it_target) == config


def test_forced_deploy_restarts_xray_and_keeps_config(
    e2e: E2eRepo,
    first_deploy: subprocess.CompletedProcess[str],
    it_target: ItTarget,
) -> None:
    _ok(first_deploy)
    _, since = _xray_state(it_target)
    config = _live_config_sha(it_target)

    _ok(
        e2e.arium(
            "fleet",
            "deploy",
            "--limit",
            NODE,
            "--via",
            "direct",
            "--force",
            "--yes",
        )
    )

    active, after = _xray_state(it_target)
    assert active == "active"
    assert after != since
    assert _live_config_sha(it_target) == config
