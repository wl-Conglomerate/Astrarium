"""RolloutController wired to fakes (stub app, stub topology, FakeTransport): no HexRift, sops or SSH."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import yaml
from hexrift.errors import Error as HexRiftError

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import Manifest
from astrarium.components.rollout.controller import DeployOptions, RolloutController
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.sshcfg.render import SshPaths
from astrarium.components.topology.bridge import BuiltNode, HexRiftNode
from astrarium.components.topology.controller import BuildContext
from astrarium.components.versions.upstream import UpstreamClient
from astrarium.repo import Repo
from astrarium.runtime import RuntimeDir
from tests.support.deployment import git
from tests.support.fake_transport import FakeTransport, ScriptedNode
from tests.support.fake_upstream import FakeUpstream


CONFIG = "{}\n"

CONFIG_SHA = hashlib.sha256(CONFIG.encode()).hexdigest()


class FakeKeys:
    """HexRift keys controller stand-in: records forced exit rotations.

    `fail`, set by test after construction, maps node id to message `gen_keys` raises as
    `HexRiftError` instead of rotating, for exercising failure path.
    """

    def __init__(self) -> None:
        self.rotated: list[str] = []
        self.fail: dict[str, str] = {}

    def gen_keys(self, node_id: str, keys_dir: Path, force: bool = False) -> bool:
        if not force:
            raise AssertionError("exit rotation runs only with force")
        if node_id in self.fail:
            raise HexRiftError(self.fail[node_id])
        self.rotated.append(node_id)
        (keys_dir / f"{node_id}.yaml").write_text(yaml.safe_dump({"reality_private_key": f"rotated-{node_id}-key"}))
        return True


class StubTopology:
    """TopologyController stand-in: prepare/require_keys/build without HexRift or sops."""

    def require_keys(self, ctx: BuildContext, node_ids: Any) -> None:
        return None

    def __init__(self, manifest: Manifest, nodes: dict[str, EffectiveNode], configs: dict[str, str]) -> None:
        self.manifest = manifest
        self.nodes = nodes
        self.configs = configs
        self.keys = FakeKeys()

    def prepare(self, runtime: RuntimeDir, *, need_keys: bool) -> BuildContext:
        keys_dir = runtime.sub("keys")
        hexrift = {}
        for node_id, node in self.nodes.items():
            if node.is_hexrift:
                (keys_dir / f"{node_id}.yaml").write_text(yaml.safe_dump({"reality_private_key": f"old-{node_id}"}))
                kind = "exit" if node.root_role == "exit" else "hub"
                hexrift[node_id] = HexRiftNode(
                    node_id,
                    node.region,
                    kind,
                    f"{node_id}.example.net",
                )
        return BuildContext(
            runtime=runtime,
            manifest=self.manifest,
            overlay={},
            topology=runtime.path / "topology.yaml",
            app=cast(Any, SimpleNamespace(keys=self.keys)),
            hexrift=hexrift,
            nodes=self.nodes,
            keys_dir=keys_dir,
            masker=ValueMasker(),
        )

    def build(self, ctx: BuildContext, node_ids: list[str], out_dir: Path) -> dict[str, BuiltNode]:
        built = {}
        for node_id in node_ids:
            directory = out_dir / node_id
            directory.mkdir()
            (directory / "config.json").write_text(self.configs.get(node_id, CONFIG))
            (directory / "haproxy.cfg").write_text("global\n")
            built[node_id] = BuiltNode(
                node_id,
                directory / "config.json",
                directory / "haproxy.cfg",
                False,
            )
        return built


class NotifyStub:
    """NotifyController stand-in recording deploy_summary calls."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def deploy_summary(self, discord: Any, **kwargs: Any) -> int:
        self.calls.append(kwargs)
        return 204


@dataclass
class RolloutEnv:
    controller: RolloutController
    transport: FakeTransport
    topology: StubTopology
    repo: Repo
    notify: NotifyStub
    stored: list[str] = field(default_factory=list)


def rollout_env(
    tmp_path: Path,
    nodes: dict[str, EffectiveNode],
    fakes: dict[str, ScriptedNode],
    *,
    manifest_extra: dict[str, Any] | None = None,
    configs: dict[str, str] | None = None,
) -> RolloutEnv:
    """Committed deployment repo in tmp_path, controller with fakes injected."""

    root = tmp_path / "deployment"
    root.mkdir()
    git(
        root,
        "init",
        "-q",
        "-b",
        "main",
    )
    (root / "astrarium.yaml").write_text("deployment: {name: test}\n")
    git(
        root,
        "add",
        "astrarium.yaml",
    )
    git(
        root,
        "commit",
        "-q",
        "-m",
        "initial",
    )
    raw = {
        "deployment": {"name": "test", "domain": "example.net"},
        "nodes": {node_id: {"role": node.role, "ipv4": node.ipv4} for node_id, node in nodes.items()},
        **(manifest_extra if manifest_extra is not None else {}),
    }
    topology = StubTopology(
        Manifest.model_validate(raw),
        nodes,
        configs if configs is not None else {},
    )
    notify = NotifyStub()
    repo = Repo(root)
    app = SimpleNamespace(
        repo=repo,
        topology=topology,
        sops=None,
        notify=notify,
    )
    controller = RolloutController(cast(Any, app))
    transport = FakeTransport(fakes)
    env = RolloutEnv(
        controller,
        transport,
        topology,
        repo,
        notify,
    )
    wire_fakes(
        controller,
        transport,
        lambda node_id, path: env.stored.append(node_id),
    )
    return env


def wire_fakes(controller: RolloutController, transport: FakeTransport, store: Callable[[str, Path], None]) -> None:
    """Inject transport (scoped to paths.nodes on every call), FakeUpstream and key store into controller."""

    def make_transport(paths: SshPaths, jumped: frozenset[str]) -> FakeTransport:
        transport.scope = paths.nodes
        return transport

    controller.make_transport = make_transport
    controller.make_upstream = lambda cache: cast(UpstreamClient, FakeUpstream())
    controller.make_keystore = lambda: cast(KeyStore, SimpleNamespace(store=store))


def options(**overrides: Any) -> DeployOptions:
    """DeployOptions with test defaults (no waits), overridden per test."""

    values: dict[str, Any] = {
        "limit": None,
        "canary": None,
        "canary_wait": 0.0,
        "stagger": 0.0,
        "force": False,
        "dry_run": False,
        "via": None,
        "artifacts": {},
        "rotate_exit_keys": False,
        "allow_dirty": False,
        "notify": False,
    }
    values.update(overrides)
    return DeployOptions(**values)
