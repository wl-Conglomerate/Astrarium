"""`check`: build base and head with throwaway material, test head configs, report changes."""

from __future__ import annotations

import json
import logging
import os
import platform
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

import httpx
from hexrift.app import HexRiftApp

from astrarium.components.check.geodata import ensure_geodata
from astrarium.components.check.report import (
    CheckReport,
    config_recipients,
    diff_nodes,
    file_recipients,
    overlay_changes,
    recipient_changes,
    render_markdown,
    renderer_warning,
    secrets_file_changes,
    tool_stack_changes,
    version_changes,
)
from astrarium.components.check.revisions import code_diff, head_label, materialize_revision, resolve_base
from astrarium.components.check.runners import (
    DEFAULT_HAPROXY_IMAGE,
    CheckResult,
    HaproxyTools,
    haproxy_step,
    haproxy_tools,
    run_xray_test,
)
from astrarium.components.check.standins import TlsPair, haproxy_test_config, make_tls_pair, xray_test_config
from astrarium.components.check.throwaway import random_namespace, standin_overlay, throwaway_keys
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.loader import load_manifest, parse_raw, read_raw
from astrarium.components.manifest.models import ARCH_BY_MACHINE, Arch, VersionPin, XrayRelease
from astrarium.components.rollout.artifacts import GOARCH, XRAY_REPO, ArtifactResolver, XrayArtifact, head_commit
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.topology.bridge import BuiltNode, HexRiftNode, build_nodes
from astrarium.components.topology.controller import derive_checked, require_domain
from astrarium.components.versions.registry import lock_versions
from astrarium.components.versions.upstream import UpstreamClient
from astrarium.core import BaseController
from astrarium.errors import AstrariumError, Refused, UsageProblem
from astrarium.parallel import run_pool
from astrarium.repo import Repo
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp

LOG = logging.getLogger(__name__)

NO_HAPROXY = "no haproxy binary, podman or docker"

BuildScope = Literal["check", "deploy"]


def _yaml(path: Path) -> dict[str, Any]:
    return read_raw(path) if path.is_file() else {}


class CheckFailed(AstrariumError):
    """At least one xray or haproxy test failed (exit 1)."""


class Reachability(Protocol):
    """Subset of UpstreamClient used to vet main@ pins."""

    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool: ...


@dataclass(frozen=True)
class XrayBuild:
    """One xray HEAD build for CI: commit, manifest arch, Go arch."""

    sha: str
    arch: Arch
    goarch: str


class XrayResolver(Protocol):
    """Subset of rollout ArtifactResolver used by check."""

    def resolve(self, pin: VersionPin, arch: Arch, provided: Mapping[Arch, Path]) -> XrayArtifact: ...


@dataclass(frozen=True)
class CheckOptions:
    """Inputs of one `arium repo check` run."""

    base: str = "origin/main"
    report_md: Path | None = None
    xray_bin: Path | None = None
    artifacts: Mapping[Arch, Path] = field(default_factory=dict)
    haproxy_bin: Path | None = None
    haproxy_image: str = DEFAULT_HAPROXY_IMAGE
    geo_dir: Path | None = None


@dataclass(frozen=True)
class TreeFiles:
    """Plain file reads of one revision: never decrypted, never built."""

    raw: dict[str, Any]
    overlay: dict[str, Any]
    sops_config: dict[str, Any]
    secrets: dict[str, dict[str, Any]]
    lock: str


EMPTY_TREE = TreeFiles(
    raw={},
    overlay={},
    sops_config={},
    secrets={},
    lock="",
)


@dataclass(frozen=True)
class Build:
    """HexRift app and effective nodes of one revision."""

    app: HexRiftApp
    hexrift: dict[str, HexRiftNode]
    nodes: dict[str, EffectiveNode]


def read_tree(root: Path) -> TreeFiles:
    """Manifest, encrypted overlay, sops config, secrets metadata and lock text under `root`."""

    repo = Repo(root)
    secrets = {str(path.relative_to(root)): _yaml(path) for path in sorted((root / "secrets").rglob("*.yaml"))}
    lock = repo.lockfile.read_text() if repo.lockfile.is_file() else ""
    return TreeFiles(
        raw=_yaml(repo.manifest),
        overlay=_yaml(repo.overlay),
        sops_config=_yaml(repo.sops_config),
        secrets=secrets,
        lock=lock,
    )


def _base_input[T](warnings: list[str], rel: str, read: Callable[[], T], probe: Callable[[T], object]) -> T | None:
    try:
        value = read()
        probe(value)
    except Exception as e:  # base best effort: unreadable or malformed input -> None, caller substitutes empty
        reason = e.message if isinstance(e, AstrariumError) else f"{type(e).__name__}: {e}"
        warnings.append(f"base {rel} unusable ({reason}), compared as empty")
        return None
    return value


def read_base_tree(root: Path, warnings: list[str]) -> TreeFiles:
    """read_tree for base revision: unreadable or malformed input warned, compared as empty (secrets file: absent)."""

    repo = Repo(root)

    def text(path: Path) -> str:
        return path.read_text(encoding="utf-8") if path.is_file() else ""

    def yaml_file(path: Path, probe: Callable[[dict[str, Any]], object]) -> dict[str, Any] | None:
        rel = path.relative_to(root).as_posix()
        return _base_input(
            warnings,
            rel,
            lambda: parse_raw(text(path), f"base {rel}"),
            probe,
        )

    secrets: dict[str, dict[str, Any]] = {}
    for path in sorted((root / "secrets").rglob("*.yaml")):
        if (data := yaml_file(path, file_recipients)) is not None:
            secrets[path.relative_to(root).as_posix()] = data
    raw = yaml_file(repo.manifest, lambda value: version_changes(value, {}))
    sops_config = yaml_file(repo.sops_config, config_recipients)
    lock = _base_input(
        warnings,
        repo.lockfile.name,
        lambda: text(repo.lockfile),
        lock_versions,
    )
    return TreeFiles(
        raw=raw if raw is not None else {},
        overlay=secrets.get(repo.overlay.relative_to(root).as_posix(), {}),
        sops_config=sops_config if sops_config is not None else {},
        secrets=secrets,
        lock=lock if lock is not None else "",
    )


def load_build(root: Path, workdir: Path, namespace: str, overlay: Mapping[str, Any]) -> Build:
    """Manifest with stand-in overlay, topology with throwaway namespace, effective nodes.

    Applies domain and hub/exit consistency rules of build/deploy
    (topology.controller.require_domain/derive_checked, also used by TopologyController.prepare).
    """

    repo = Repo(root)
    manifest = load_manifest(repo, standin_overlay(overlay))
    require_domain(manifest)
    app, hexrift, nodes = derive_checked(
        manifest,
        repo.topology,
        workdir / "topology.yaml",
        namespace,
    )
    return Build(
        app=app,
        hexrift=hexrift,
        nodes=nodes,
    )


def machine_arch() -> Arch:
    """Arch of this machine in manifest terms."""

    machine = platform.machine().lower()
    if machine not in ARCH_BY_MACHINE:
        raise UsageProblem(f"unsupported machine architecture {machine!r}")
    return ARCH_BY_MACHINE[machine]


def _masker(namespace: str, *key_dirs: Path) -> ValueMasker:
    masker = ValueMasker()
    masker.add(namespace)
    for key_dir in key_dirs:
        for key_file in sorted(key_dir.glob("*.yaml")):
            masker.add_many(str(value) for value in read_raw(key_file).values())
    return masker


def _xray_test(
    node_id: str,
    built: BuiltNode,
    binary: Path,
    assets: Path,
    pair: TlsPair,
    workdir: Path,
    masker: ValueMasker,
) -> CheckResult:
    config = workdir / f"{node_id}.json"
    config.write_text(
        json.dumps(
            xray_test_config(
                json.loads(built.config_json.read_text()),
                pair,
                workdir,
            ),
            indent=2,
        )
    )
    passed, output = run_xray_test(
        binary,
        config,
        assets,
    )
    return CheckResult(
        node_id,
        "xray",
        "passed" if passed else "failed",
        masker.mask(output),
    )


def _haproxy_test(
    node_id: str,
    node: EffectiveNode,
    built: BuiltNode,
    tools: HaproxyTools,
    pair: TlsPair,
    workdir: Path,
    masker: ValueMasker,
    mismatched: set[str],
) -> CheckResult:
    haproxy = node.features["haproxy"]
    step = haproxy_step(bool(haproxy["install"]), built.haproxy_wanted)
    if step == "skip":
        return CheckResult(
            node_id,
            "haproxy",
            "skipped",
            "haproxy not installed on node",
        )
    if step == "fail":
        detail = "topology renders HAProxy but features.haproxy.install is false"
        return CheckResult(
            node_id,
            "haproxy",
            "failed",
            detail,
        )
    version = str(haproxy["version"])
    checker, differs = tools.checker(version)
    if checker is None:
        return CheckResult(
            node_id,
            "haproxy",
            "skipped",
            NO_HAPROXY,
        )
    if differs:
        mismatched.add(version)
    config = workdir / "haproxy.cfg"
    config.write_text(
        haproxy_test_config(
            built.haproxy_cfg.read_text(),
            workdir,
            pair,
        )
    )
    passed, output = checker.check(
        config,
        workdir,
        version,
    )
    return CheckResult(
        node_id,
        "haproxy",
        "passed" if passed else "failed",
        masker.mask(output),
    )


def _unbuilt_warning(arch: Arch, shas: Mapping[str, list[str]]) -> str:
    built, *others = shas
    nodes = ", ".join(sorted(node_id for sha in others for node_id in shas[sha]))
    return (
        f"several main@ pins for {arch}: check builds main@{built[:12]} only, xray -test skipped on {nodes} "
        "(align main@ pins to test every node)"
    )


def _main_shas(head: Build, arch_of: Callable[[EffectiveNode], Arch]) -> dict[Arch, dict[str, list[str]]]:
    """main@ commits per build arch, in node order, each with its nodes."""

    found: dict[Arch, dict[str, list[str]]] = {}
    for node_id in sorted(head.hexrift):
        node = head.nodes[node_id]
        pin = node.versions.get("xray")
        sha = head_commit(pin) if pin is not None else None
        if sha is not None:
            found.setdefault(arch_of(node), {}).setdefault(sha, []).append(node_id)
    return found


class CheckController(BaseController["AstrariumApp"]):
    """PR check without age key or SSH key."""

    def run(
        self,
        opts: CheckOptions,
        *,
        resolver: XrayResolver | None = None,
        http: httpx.Client | None = None,
    ) -> CheckReport:
        """Build base and head, test head configs, return report (written to `opts.report_md` when set)."""

        repo = self.app.repo
        base_sha = resolve_base(repo.root, opts.base)
        warnings: list[str] = []
        with RuntimeDir() as runtime:
            namespace = random_namespace()
            head_files = read_tree(repo.root)
            head = load_build(
                repo.root,
                runtime.sub("head"),
                namespace,
                head_files.overlay,
            )
            base_files, base = self._load_base(
                repo.root,
                base_sha,
                runtime,
                namespace,
                warnings,
            )
            head_keys, base_keys = throwaway_keys(
                head.app,
                base.app if base else None,
                runtime.sub("keys"),
            )
            masker = _masker(
                namespace,
                head_keys,
                base_keys,
            )
            head_built = build_nodes(
                head.app,
                sorted(head.hexrift),
                head_keys,
                runtime.sub("head-out"),
            )
            base_built = self._build_base(
                base,
                base_keys,
                runtime,
                warnings,
            )
            tests = self._tests(
                head,
                head_built,
                runtime,
                opts,
                masker,
                resolver,
                http,
                warnings,
            )
            tool_stack = tool_stack_changes(base_files.lock, head_files.lock)
            report = CheckReport(
                base=base_sha[:12],
                head=head_label(repo.root),
                nodes=diff_nodes(
                    base_built,
                    head_built,
                    masker,
                ),
                tests=tests,
                versions=version_changes(base_files.raw, head_files.raw),
                tool_stack=tool_stack,
                overlay=overlay_changes(base_files.overlay, head_files.overlay),
                recipients=recipient_changes(
                    base_files.sops_config,
                    head_files.sops_config,
                    base_files.secrets,
                    head_files.secrets,
                ),
                code_diff=code_diff(repo.root, base_sha),
                warnings=[*warnings, *renderer_warning(tool_stack)],
                secrets_files=secrets_file_changes(base_files.secrets, head_files.secrets),
            )
        if opts.report_md is not None:
            opts.report_md.write_text(render_markdown(report))
        return report

    def xray_builds(self, scope: BuildScope, runner: Arch, *, upstream: Reachability | None = None) -> list[XrayBuild]:
        """main@ builds CI compiles (runner arch for check, node archs for deploy), commits off upstream main refused.

        Check scope builds first commit per arch in node order, `check` skips nodes on other commits.
        """

        repo = self.app.repo
        with RuntimeDir() as runtime:
            head = load_build(
                repo.root,
                runtime.sub("head"),
                random_namespace(),
                read_tree(repo.root).overlay,
            )
        wanted = _main_shas(head, lambda node: runner if scope == "check" else node.arch)
        crowded: list[Arch] = []
        for arch, shas in wanted.items():
            if len(shas) > 1:
                crowded.append(arch)
        crowded.sort()
        if crowded and scope == "deploy":
            raise UsageProblem(
                f"several main@ pins for {', '.join(crowded)}",
                hint="--artifact takes one build per architecture: align main@ pins, or deploy nodes on other pins "
                "from a laptop with --limit and a hand-built --artifact",
            )
        for arch in crowded:
            LOG.warning(_unbuilt_warning(arch, wanted[arch]))
        client = upstream if upstream is not None else UpstreamClient(repo.cache_dir, os.environ.get("GITHUB_TOKEN"))
        builds: list[XrayBuild] = []
        for arch, shas in sorted(wanted.items()):
            sha = next(iter(shas))
            if not client.is_reachable(XRAY_REPO, sha):
                raise Refused(
                    f"main@{sha} is not on {XRAY_REPO} main",
                    hint="pin commits from upstream main, e.g. `arium versions bump xray main@latest`",
                )
            builds.append(
                XrayBuild(
                    sha=sha,
                    arch=arch,
                    goarch=GOARCH[arch],
                )
            )
        return builds

    def _load_base(
        self,
        root: Path,
        base_sha: str,
        runtime: RuntimeDir,
        namespace: str,
        warnings: list[str],
    ) -> tuple[TreeFiles, Build | None]:
        try:
            tree = materialize_revision(
                root,
                base_sha,
                runtime.sub("base-tree"),
            )
        except AstrariumError as e:
            warnings.append(f"base files unreadable ({e.message}), every head node reported as added")
            return EMPTY_TREE, None
        files = read_base_tree(tree, warnings)
        if not (tree / "astrarium.yaml").is_file() or not (tree / "topology.yaml").is_file():
            warnings.append("base has no astrarium.yaml or topology.yaml: every head node reported as added")
            return files, None
        try:
            return files, load_build(
                tree,
                runtime.sub("base"),
                namespace,
                files.overlay,
            )
        except Exception as e:  # base best effort: any failure -> report without base
            warnings.append(f"base does not load with this tool stack ({e}); every head node reported as added")
            return files, None

    def _build_base(
        self,
        base: Build | None,
        keys: Path,
        runtime: RuntimeDir,
        warnings: list[str],
    ) -> dict[str, BuiltNode]:
        if base is None:
            return {}
        try:
            return build_nodes(
                base.app,
                sorted(base.hexrift),
                keys,
                runtime.sub("base-out"),
            )
        except Exception as e:  # base best effort
            warnings.append(f"base build failed ({e}); every head node reported as added")
            return {}

    def _tests(
        self,
        head: Build,
        built: Mapping[str, BuiltNode],
        runtime: RuntimeDir,
        opts: CheckOptions,
        masker: ValueMasker,
        resolver: XrayResolver | None,
        http: httpx.Client | None,
        warnings: list[str],
    ) -> list[CheckResult]:
        pair = make_tls_pair(runtime.sub("tls"))
        binaries = self._xray_binaries(
            head,
            sorted(built),
            opts,
            runtime,
            resolver,
            warnings,
        )
        haproxy = haproxy_tools(opts.haproxy_bin, opts.haproxy_image)
        asset_dir: Path | None = None
        if any(isinstance(choice, Path) for choice in binaries.values()):
            asset_dir = opts.geo_dir or self._geodata(http, warnings)
        mismatched: set[str] = set()

        def one(node_id: str) -> list[CheckResult]:
            node_results: list[CheckResult] = []
            choice = binaries[node_id]
            if isinstance(choice, Path):
                if asset_dir is not None:
                    node_results.append(
                        _xray_test(
                            node_id,
                            built[node_id],
                            choice,
                            asset_dir,
                            pair,
                            runtime.sub("xray-test"),
                            masker,
                        )
                    )
            else:
                node_results.append(choice)
            workdir = runtime.sub(f"haproxy-{node_id}")
            node = head.nodes[node_id]
            node_results.append(
                _haproxy_test(
                    node_id,
                    node,
                    built[node_id],
                    haproxy,
                    pair,
                    workdir,
                    masker,
                    mismatched,
                )
            )
            return node_results

        # xray -test and haproxy -c are subprocess-bound: per-node tests run on thread pool
        results: list[CheckResult] = [
            result for node_results in run_pool(one, sorted(built)) for result in node_results
        ]
        if haproxy.preferred is None and any(result.detail == NO_HAPROXY for result in results):
            warnings.append(f"{NO_HAPROXY}: haproxy -c skipped")
        if mismatched:
            local = haproxy.local_version or "of unknown version"
            warnings.append(
                f"haproxy -c used local haproxy {local} for nodes pinned to {', '.join(sorted(mismatched))}: "
                "results may differ on nodes, podman or docker would test with matching image"
            )
        return results

    def _xray_binaries(
        self,
        head: Build,
        node_ids: list[str],
        opts: CheckOptions,
        runtime: RuntimeDir,
        resolver: XrayResolver | None,
        warnings: list[str],
    ) -> dict[str, Path | CheckResult]:
        choices: dict[str, Path | CheckResult] = {}
        explicit = opts.xray_bin
        if explicit is not None:
            for node_id in node_ids:
                choices[node_id] = explicit
            return choices
        if not sys.platform.startswith("linux"):
            detail = "xray release binaries need Linux; pass --xray-bin"
            for node_id in node_ids:
                choices[node_id] = CheckResult(
                    node_id,
                    "xray",
                    "skipped",
                    detail,
                )
            return choices
        arch = machine_arch()
        active = resolver if resolver is not None else self._default_resolver(runtime)
        main_shas = _main_shas(head, lambda _node: arch).get(arch, {})
        unbuilt = set(list(main_shas)[1:])
        arch_gaps: set[tuple[str, str]] = set()
        for node_id in node_ids:
            node = head.nodes[node_id]
            pin = node.versions.get("xray")
            if pin is None:
                choices[node_id] = CheckResult(
                    node_id,
                    "xray",
                    "skipped",
                    "no versions.xray pin",
                )
                continue
            if isinstance(pin, XrayRelease) and arch not in pin.sha256:
                choices[node_id] = CheckResult(
                    node_id,
                    "xray",
                    "skipped",
                    f"xray {pin.version} has no sha256 for {arch} in astrarium.yaml",
                )
                override = node.provenance.get("versions.xray") == "node"
                arch_gaps.add((pin.version, f" --node {node_id}" if override else ""))
                continue
            if not isinstance(pin, XrayRelease) and head_commit(pin) in unbuilt:
                detail = f"CI builds one main@ commit for {arch}, not {pin}"
                choices[node_id] = CheckResult(
                    node_id,
                    "xray",
                    "skipped",
                    detail,
                )
                continue
            try:
                choices[node_id] = active.resolve(
                    pin,
                    arch,
                    opts.artifacts,
                ).binary
            except AstrariumError as e:
                choices[node_id] = CheckResult(
                    node_id,
                    "xray",
                    "failed",
                    e.message,
                )
        if unbuilt:
            warnings.append(_unbuilt_warning(arch, main_shas))
        warnings.extend(
            f"xray {version} has no sha256 for {arch}: -test skipped, run `arium versions bump xray {version}{node}`"
            for version, node in sorted(arch_gaps)
        )
        return choices

    def _default_resolver(self, runtime: RuntimeDir) -> ArtifactResolver:
        repo = self.app.repo
        upstream = UpstreamClient(repo.cache_dir, os.environ.get("GITHUB_TOKEN"))
        return ArtifactResolver(
            upstream,
            repo.cache_dir,
            runtime,
        )

    def _geodata(self, http: httpx.Client | None, warnings: list[str]) -> Path:
        if http is not None:
            geo = ensure_geodata(self.app.repo.cache_dir, http)
        else:
            with httpx.Client(timeout=120.0) as client:
                geo = ensure_geodata(self.app.repo.cache_dir, client)
        if geo.warning is not None:
            warnings.append(geo.warning)
        return geo.path
