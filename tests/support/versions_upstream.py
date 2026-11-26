"""Versions test support: in-memory release source, fake application pieces, versions controller on fakes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from astrarium.components.inventory.controller import InventoryController
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import Manifest
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.sshcfg.render import SshPaths
from astrarium.components.versions.controller import VersionsController
from astrarium.components.versions.upstream import Asset, Release
from astrarium.errors import ExternalToolError
from astrarium.repo import Repo
from astrarium.runtime import RuntimeDir
from tests.support.fleet import FakeRunner, TransportPool, controller_with


@dataclass(frozen=True)
class PreRelease(Release):
    """Fake-side prerelease marker: latest(pre=False) skips it, production dataclass carries no flag."""

    prerelease: bool = True


def make_release(tag: str, *, pre: bool = False, assets: Mapping[str, str | None] | None = None) -> Release:
    """Release whose assets map name -> API digest (None = no digest), URLs under example.invalid."""

    listed = {} if assets is None else dict(assets)
    release_cls = PreRelease if pre else Release
    return release_cls(
        tag=tag,
        assets={
            name: Asset(
                name=name,
                url=f"https://example.invalid/{tag}/{name}",
                digest=digest,
            )
            for name, digest in listed.items()
        },
    )


@dataclass
class ReleaseSource:
    """UpstreamClient stand-in: releases newest first per repo, branch heads, reachable commits, download bodies."""

    releases: dict[str, list[Release]] = field(default_factory=dict)
    heads: dict[str, str] = field(default_factory=dict)
    reachable: set[str] = field(default_factory=set)
    files: dict[str, bytes] = field(default_factory=dict)
    calls: list[tuple[str, ...]] = field(default_factory=list)

    def release(self, repo: str, tag: str) -> Release:
        self.calls.append(
            (
                "release",
                repo,
                tag,
            )
        )
        for item in self.releases.get(repo, []):
            if item.tag == tag:
                return item
        raise ExternalToolError(f"GitHub: {repo} has no release {tag}")

    def latest(self, repo: str, *, pre: bool) -> Release:
        self.calls.append(("latest", repo))
        for item in self.releases.get(repo, []):
            if pre or not isinstance(item, PreRelease):
                return item
        raise ExternalToolError(f"GitHub: {repo} has no release")

    def head_sha(self, repo: str, branch: str = "main") -> str:
        self.calls.append(
            (
                "head",
                repo,
                branch,
            )
        )
        if repo not in self.heads:
            raise ExternalToolError(f"GitHub: {repo} has no branch {branch}")
        return self.heads[repo]

    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool:
        self.calls.append(
            (
                "reachable",
                repo,
                sha,
            )
        )
        return sha in self.reachable

    def download(self, url: str, dest: Path) -> Path:
        self.calls.append(("download", url))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.files[url])
        return dest


@dataclass
class FakeTopology:
    """TopologyController.prepare stand-in: fixed manifest and effective nodes, no sops or HexRift."""

    manifest: Manifest
    nodes: dict[str, EffectiveNode]
    masker: ValueMasker = field(default_factory=ValueMasker)

    def prepare(self, runtime: RuntimeDir, *, need_keys: bool) -> Any:
        return SimpleNamespace(
            runtime=runtime,
            manifest=self.manifest,
            nodes=self.nodes,
            masker=self.masker,
        )


@dataclass
class FakeApp:
    """Application attributes versions controller reaches: repo, topology, inventory."""

    repo: Repo
    topology: FakeTopology | None
    inventory: InventoryController


def versions_controller(
    repo: Repo,
    *,
    upstream: ReleaseSource | None = None,
    topology: FakeTopology | None = None,
    pool: TransportPool | None = None,
    runner: FakeRunner | None = None,
) -> VersionsController:
    """VersionsController on fakes: release source, scripted transports, fake casts."""

    source = ReleaseSource() if upstream is None else upstream
    transports = TransportPool() if pool is None else pool
    casts = FakeRunner() if runner is None else runner
    app = FakeApp(
        repo=repo,
        topology=topology,
        inventory=controller_with(casts, transports),
    )

    class _Controller(VersionsController):
        def make_upstream(self) -> Any:
            return source

        def make_transport(self, paths: SshPaths, jumped: frozenset[str]) -> Any:
            return transports(paths, jumped)

    return _Controller(cast(Any, app))
