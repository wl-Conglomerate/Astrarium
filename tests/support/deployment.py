"""Fixture deployment builder: copies tests/fixtures/deployment, encrypts overlay and HexRift keys (FakeSops)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from astrarium.app import AstrariumApp
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.secrets.sops import Sops
from astrarium.components.topology.bridge import gen_keys, hexrift_nodes, materialize_topology, open_hexrift
from astrarium.repo import Repo
from tests.support.fake_sops import FakeSops, write_encrypted


FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "deployment"

NAMESPACE = "fixture-namespace-0123456789abcdef"

TELEMT_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

WEBHOOK = "https://discord.example.invalid/api/webhooks/1/fixture-token-value"

GIT = (
    "git",
    "-c",
    "user.name=t",
    "-c",
    "user.email=t@example.invalid",
    "-c",
    "commit.gpgsign=false",
)


def overlay_data() -> dict[str, Any]:
    return {
        "topology": {"namespace": NAMESPACE},
        "notify": {"discord": {"webhook_url": WEBHOOK}},
        "roles": {"pulsar": {"features": {"telemt": {"users": {"alice": TELEMT_SECRET}}}}},
    }


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        [
            *GIT,
            "-C",
            str(root),
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def generate_keys(root: Path, sops: Sops, node_ids: list[str] | None = None) -> list[str]:
    """HexRift keys for `node_ids` (default: every topology node) encrypted into secrets/keys."""

    repo = Repo(root)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        app = open_hexrift(
            materialize_topology(
                repo.topology,
                work / "topology.yaml",
                NAMESPACE,
            )
        )
        wanted = sorted(hexrift_nodes(app)) if node_ids is None else node_ids
        created = gen_keys(
            app,
            wanted,
            work / "keys",
        )
        store = KeyStore(repo, sops)
        for node_id in created:
            store.store(node_id, work / "keys" / f"{node_id}.yaml")
    return created


def git_commit_all(root: Path, message: str = "fixture") -> None:
    """Init repo on main when needed, commit everything."""

    if not (root / ".git").exists():
        subprocess.run(
            [
                *GIT,
                "-C",
                str(root),
                "init",
                "-q",
                "-b",
                "main",
            ],
            check=True,
            capture_output=True,
        )
    subprocess.run(
        [
            *GIT,
            "-C",
            str(root),
            "add",
            "-A",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            *GIT,
            "-C",
            str(root),
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        ],
        check=True,
        capture_output=True,
    )


def make_deployment(root: Path, sops: Sops | None = None, *, keys: bool = True, git: bool = False) -> Path:
    """Fixture deployment at `root`: overlay encrypted, key files for every hub/exit unless `keys=False`."""

    shutil.copytree(FIXTURE, root)
    active = FakeSops() if sops is None else sops
    write_encrypted(
        active,
        Repo(root).overlay,
        overlay_data(),
        root,
    )
    if keys:
        generate_keys(root, active)
    if git:
        git_commit_all(root)
    return root


def fixture_app(root: Path, sops: Sops | None = None) -> AstrariumApp:
    """AstrariumApp on `root` with FakeSops."""

    app = AstrariumApp(root)
    app.sops = FakeSops() if sops is None else sops
    return app
