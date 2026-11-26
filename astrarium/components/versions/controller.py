"""Versions: list, outdated, bump and apply of component pins, plus versions part of status."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import tomllib
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from packaging.version import InvalidVersion, Version
from pydantic import ValidationError

from astrarium.components.inventory.batches import cast_batches
from astrarium.components.inventory.controller import (
    DONE,
    CastPlan,
    CastPreview,
    CastReport,
    Stage,
    Verifier,
    bastion_skip,
    check_targets,
    log_cast_run,
    preview_of,
)
from astrarium.components.inventory.paths import NO_BASTION_LOGIN, CastIdentity, check_cast_identity
from astrarium.components.inventory.runes import resolve_rune
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.edit import ManifestEditor
from astrarium.components.manifest.loader import load_manifest
from astrarium.components.manifest.models import HEXRIFT_ROLES, Arch, Identity, Manifest, VersionPin, XrayRelease
from astrarium.components.manifest.presets import root_role
from astrarium.components.rollout.artifacts import XRAY_ASSETS, XRAY_REPO, sha256_file
from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.schedule import build_schedule
from astrarium.components.rollout.selection import Selection, parse_limit, select
from astrarium.components.rollout.transport import OpenSshTransport, Transport, write_scoped_ssh
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.sshcfg.render import JUMP_CONCURRENCY, SshPaths, Via, resolve_via
from astrarium.components.versions.changes import PinChanges, changed_since
from astrarium.components.versions.probe import (
    InstalledVersion,
    VersionCell,
    installed_label,
    node_cells,
    pin_label,
    pin_matches,
    probe_nodes,
)
from astrarium.components.versions.registry import (
    MAIN_PIN,
    Component,
    Owner,
    apply_label,
    build_registry,
    check_pins,
    feature_enabled,
    listed_components,
    lock_versions,
    pin_layer,
    tag_for,
    tool_stack_versions,
    unmapped_nullforge_components,
    version_from_tag,
    version_key,
)
from astrarium.components.versions.upstream import Asset, Release, UpstreamClient
from astrarium.core import BaseController
from astrarium.errors import AstrariumError, ExternalToolError, Refused, UsageProblem
from astrarium.repo import Repo, ensure_clean
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp  # noqa: F401

Probes = dict[str, dict[str, InstalledVersion] | None]
"""Node id -> probe results per component, None when node's probe command failed."""

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")

COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$")

PIN_TEXT = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
"""Release pins and tool stack versions: one token, never specifier list or option."""

UV_DROPPED_ENV = frozenset(
    {
        "UV_CONFIG_FILE",
        "UV_CONSTRAINT",
        "UV_DEFAULT_INDEX",
        "UV_EXCLUDE_NEWER",
        "UV_EXTRA_INDEX_URL",
        "UV_FIND_LINKS",
        "UV_FORK_STRATEGY",
        "UV_FROZEN",
        "UV_INDEX",
        "UV_INDEX_STRATEGY",
        "UV_INDEX_URL",
        "UV_KEYRING_PROVIDER",
        "UV_LOCKED",
        "UV_NO_CONFIG",
        "UV_NO_SOURCES",
        "UV_NO_SOURCES_PACKAGE",
        "UV_OFFLINE",
        "UV_PRERELEASE",
        "UV_PROJECT",
        "UV_RESOLUTION",
        "UV_WORKING_DIR",
    }
)
"""Operator env settings that change resolution, lock handling or target project of `uv add` and `uv lock`.

Index credentials (`UV_INDEX_<NAME>_USERNAME`, `UV_INDEX_<NAME>_PASSWORD`) and cache settings pass through.
"""

RUNE_NOTES: Mapping[str, str] = {
    "base": "-r base also updates and upgrades every package",
    "profiles": "-r profiles rebuilds tmux from source when its pin changed",
}
"""Side effects of runes that apply pins (nullforge runes/base.py:95-103, runes/profiles.py:465-503)."""


def lookup_warnings(latest: Mapping[str, Latest]) -> list[str]:
    return [f"{name}: {item.error}" for name, item in sorted(latest.items()) if item.error is not None]


def cells_for(
    nodes: Mapping[str, EffectiveNode],
    manifest: Manifest,
    registry: Mapping[str, Component],
    names: Sequence[str],
    node_ids: Sequence[str],
    probes: Mapping[str, dict[str, InstalledVersion] | None],
) -> dict[str, list[VersionCell]]:
    return {
        node_id: node_cells(
            nodes[node_id],
            manifest,
            registry,
            names,
            probes.get(node_id),
            probed=node_id in probes,
        )
        for node_id in node_ids
    }


class Upstream(Protocol):
    """Release source used by versions: UpstreamClient or test stand-in."""

    def release(self, repo: str, tag: str) -> Release: ...

    def latest(self, repo: str, *, pre: bool) -> Release: ...

    def head_sha(self, repo: str, branch: str = "main") -> str: ...

    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool: ...

    def download(self, url: str, dest: Path) -> Path: ...


@dataclass(frozen=True)
class Latest:
    """Newest upstream release in pin form, upstream main head for xray HEAD pins, lookup error."""

    version: str | None
    head: str | None = None
    error: str | None = None


@dataclass(frozen=True)
class ComponentRow:
    name: str
    owner: Owner
    pin: str | None
    layer: str
    overrides: dict[str, str]
    latest: Latest
    apply: str
    cells: dict[str, VersionCell] = field(default_factory=dict)


@dataclass(frozen=True)
class ListOptions:
    node: str | None
    all_components: bool
    probe: bool
    via: Via | None


@dataclass(frozen=True)
class ListReport:
    node: str | None
    probed: bool
    rows: list[ComponentRow]
    warnings: list[str]


@dataclass(frozen=True)
class OutdatedRow:
    component: str
    where: str
    pin: str
    latest: str


@dataclass(frozen=True)
class OutdatedReport:
    pre: bool
    rows: list[OutdatedRow]
    warnings: list[str]


def has_head_pin(manifest: Manifest) -> bool:
    """True when any xray pin, global or per node, is main@<sha>."""

    pins = [manifest.versions.get("xray"), *(spec.overrides.versions.get("xray") for spec in manifest.nodes.values())]
    return any(isinstance(pin, str) and MAIN_PIN.fullmatch(pin) is not None for pin in pins)


def latest_versions(
    registry: Mapping[str, Component],
    names: Sequence[str],
    manifest: Manifest,
    upstream: Upstream,
    *,
    pre: bool,
) -> dict[str, Latest]:
    """Newest upstream release per component (stable unless pre), failures kept as errors, never raised."""

    heads = has_head_pin(manifest)
    found: dict[str, Latest] = {}
    for name in names:
        component = registry[name]
        if component.upstream is None:
            found[name] = Latest(None)
            continue
        try:
            release = upstream.latest(component.upstream, pre=pre)
            head = upstream.head_sha(component.upstream) if component.owner == "astrarium" and heads else None
        except AstrariumError as e:
            found[name] = Latest(None, error=f"{component.upstream}: {e.message}")
            continue
        found[name] = Latest(version_from_tag(component, release.tag), head)
    return found


def mapping_warnings() -> list[str]:
    """NullForge pinned component without registry entry (update NULLFORGE_COMPONENTS)"""

    unmapped = unmapped_nullforge_components()
    if not unmapped:
        return []
    return [f"no upstream/probe mapping for NullForge components: {', '.join(unmapped)}"]


def is_behind(pin: VersionPin, latest: Latest) -> bool:
    """Pin older than newest upstream release, or HEAD pin other than upstream main head, unknown never behind."""

    if isinstance(pin, XrayRelease):
        return latest.version is not None and version_key(pin.version) < version_key(latest.version)
    if MAIN_PIN.fullmatch(pin):
        return latest.head is not None and pin.removeprefix("main@") != latest.head
    if pin == "latest" or latest.version is None:
        return False
    return version_key(pin) < version_key(latest.version)


def latest_label(pin: VersionPin, latest: Latest) -> str:
    """Newest upstream value as pin."""

    if isinstance(pin, str) and MAIN_PIN.fullmatch(pin) and latest.head is not None:
        return f"main@{latest.head[:12]}"
    return latest.version if latest.version is not None else "?"


def pins_of(manifest: Manifest, component: Component, tool_versions: Mapping[str, str]) -> list[tuple[str, VersionPin]]:
    """(where, pin) pairs: uv.lock for tool stack, else manifest-level effective pin and node overrides."""

    if component.owner == "tooling":
        return [("uv.lock", tool_versions[component.name])] if component.name in tool_versions else []
    pin, layer = pin_layer(manifest, component.name)
    found: list[tuple[str, VersionPin]] = [(layer, pin)] if pin is not None else []
    for node_id in sorted(manifest.nodes):
        overrides = manifest.nodes[node_id].overrides.versions
        if component.name in overrides:
            found.append((f"node {node_id}", overrides[component.name]))
    return found


def outdated_rows(
    manifest: Manifest,
    registry: Mapping[str, Component],
    names: Sequence[str],
    tool_versions: Mapping[str, str],
    latest: Mapping[str, Latest],
) -> list[OutdatedRow]:
    """Pins behind upstream (`versions outdated`)."""

    rows: list[OutdatedRow] = []
    for name in names:
        newest = latest.get(name, Latest(None))
        for where, pin in pins_of(
            manifest,
            registry[name],
            tool_versions,
        ):
            if is_behind(pin, newest):
                rows.append(
                    OutdatedRow(
                        component=name,
                        where=where,
                        pin=pin_label(pin),
                        latest=latest_label(pin, newest),
                    )
                )
    return rows


def probe_plan(
    nodes: Mapping[str, EffectiveNode],
    registry: Mapping[str, Component],
    names: Sequence[str],
    node_ids: Sequence[str],
    identity: Identity,
) -> dict[str, list[Component]]:
    """Components probed per node: enabled there and probeable.

    Nodes without host_keys never probed, bastions left out for hop-only identities.
    """

    plan: dict[str, list[Component]] = {}
    for node_id in node_ids:
        node = nodes[node_id]
        if not node.host_keys or (identity in NO_BASTION_LOGIN and node.root_role == "bastion"):
            continue
        plan[node_id] = [
            registry[name]
            for name in names
            if registry[name].owner != "tooling"
            and registry[name].probe is not None
            and feature_enabled(node.features, registry[name].feature)
        ]
    return plan


async def probe_versions(
    transport: Transport,
    nodes: Mapping[str, EffectiveNode],
    registry: Mapping[str, Component],
    names: Sequence[str],
    node_ids: Sequence[str],
    *,
    identity: Identity,
    masker: ValueMasker,
) -> Probes:
    """Installed versions per probed node: one read-only command each."""

    plan = probe_plan(
        nodes,
        registry,
        names,
        node_ids,
        identity,
    )
    probes, _ = await probe_nodes(
        transport,
        list(plan),
        plan,
        masker,
    )
    return probes


def component_rows(
    manifest: Manifest,
    registry: Mapping[str, Component],
    names: Sequence[str],
    tool_versions: Mapping[str, str],
    latest: Mapping[str, Latest],
    cells: Mapping[str, Sequence[VersionCell]],
) -> list[ComponentRow]:
    """One row per listed component: pin and layer, node pins, per-node cells, latest upstream, apply path."""

    rows: list[ComponentRow] = []
    for name in names:
        component = registry[name]
        overrides: dict[str, str] = {}
        if component.owner == "tooling":
            pin, layer = tool_versions.get(name), "uv.lock"
        else:
            value, layer = pin_layer(manifest, name)
            pin = pin_label(value) if value is not None else None
            for node_id in sorted(manifest.nodes):
                node_pins = manifest.nodes[node_id].overrides.versions
                if name in node_pins:
                    overrides[node_id] = pin_label(node_pins[name])
        by_node = {node_id: cell for node_id, row in cells.items() for cell in row if cell.component == name}
        rows.append(
            ComponentRow(
                name=name,
                owner=component.owner,
                pin=pin,
                layer=layer,
                overrides=overrides,
                latest=latest.get(name, Latest(None)),
                apply=apply_label(component),
                cells=by_node,
            )
        )
    return rows


@dataclass(frozen=True)
class BumpOptions:
    component: str
    version: str
    node: str | None


@dataclass(frozen=True)
class BumpResult:
    component: str
    node: str | None
    before: str | None
    after: str
    files: list[str]


def fleet_archs(manifest: Manifest, node_id: str | None) -> list[Arch]:
    """Architectures xray release must ship: every hub/exit node or named node, plus x86_64 (check runs there)."""

    if node_id is not None:
        spec = manifest.nodes[node_id]
        if root_role(manifest, spec.role) not in HEXRIFT_ROLES:
            raise UsageProblem(f"xray runs on hub and exit nodes only, {node_id} has role {spec.role}")
        archs: set[Arch] = {spec.arch}
    else:
        archs = set()
        for spec in manifest.nodes.values():
            if root_role(manifest, spec.role) in HEXRIFT_ROLES:
                archs.add(spec.arch)
        if not archs:
            raise UsageProblem("astrarium.yaml has no hub or exit node to pin xray for")
    ordered: list[Arch] = list(archs)
    ordered.append("x86_64")
    ordered.sort()
    return ordered


def asset_sha256(asset: Asset, upstream: Upstream, work: Path) -> str:
    """sha256 of release asset: GitHub API digest when present, else hash of downloaded file."""

    if asset.digest is not None:
        value = asset.digest.lower().removeprefix("sha256:")
        if SHA256_HEX.fullmatch(value):
            return value
    path = upstream.download(asset.url, work / asset.name)
    return sha256_file(path)


def xray_pin(version: str, archs: Sequence[Arch], upstream: Upstream, work: Path) -> VersionPin:
    """xray pin: `{version, sha256}` per architecture, or `main@<sha>` reachable from upstream main."""

    if version.startswith("main@"):
        ref = version.removeprefix("main@")
        sha = upstream.head_sha(XRAY_REPO, "main") if ref == "latest" else ref.lower()
        if not COMMIT_SHA.fullmatch(sha):
            raise UsageProblem("xray HEAD pins are main@<40-hex sha> or main@latest")
        if not upstream.is_reachable(
            XRAY_REPO,
            sha,
            "main",
        ):
            raise Refused(
                f"commit {sha[:12]} is not reachable from {XRAY_REPO} main", hint="pin commits of upstream main only"
            )
        return f"main@{sha}"
    if version == "latest":
        release = upstream.latest(XRAY_REPO, pre=False)
    else:
        if not PIN_TEXT.fullmatch(version):
            raise UsageProblem(f"invalid xray version {version!r}")
        release = upstream.release(XRAY_REPO, version if version.startswith("v") else f"v{version}")
    digests: dict[Arch, str] = {}
    for arch in archs:
        asset = release.assets.get(XRAY_ASSETS[arch])
        if asset is None:
            raise Refused(f"xray {release.tag} ships no {XRAY_ASSETS[arch]} for {arch} nodes")
        digests[arch] = asset_sha256(
            asset,
            upstream,
            work,
        )
    try:
        return XrayRelease(version=release.tag, sha256=digests)
    except ValidationError:
        raise UsageProblem(f"xray tag {release.tag!r} is not vX.Y.Z") from None


def nullforge_pin(component: Component, version: str, upstream: Upstream) -> str:
    """Release pin after checking its upstream tag exists, `latest` resolves to newest stable release."""

    if component.upstream is None:
        raise UsageProblem(
            f"{component.name} has no known upstream repo",
            hint=f"set versions.{component.name} in astrarium.yaml by hand",
        )
    if version == "latest":
        return version_from_tag(component, upstream.latest(component.upstream, pre=False).tag)
    if not PIN_TEXT.fullmatch(version):
        raise UsageProblem(f"invalid version {version!r} for {component.name}")
    upstream.release(component.upstream, tag_for(component, version))
    return version


def uv_env(environ: Mapping[str, str], config_dir: Path) -> dict[str, str]:
    """Env for `uv` subprocess: dropped settings removed, XDG user and system uv.toml looked up in empty config_dir.

    Project pyproject `[tool.uv]` stays in effect, unlike under UV_NO_CONFIG. Root-owned /etc/uv/uv.toml is still read.
    """

    env = {key: value for key, value in environ.items() if key not in UV_DROPPED_ENV}
    env["XDG_CONFIG_HOME"] = str(config_dir)
    env["XDG_CONFIG_DIRS"] = str(config_dir)
    return env


def find_uv() -> str:
    """uv running this project (`UV`, exported by `uv run`), else uv on PATH."""

    found = os.environ.get("UV", "") or shutil.which("uv")
    if not found:
        raise ExternalToolError("uv not found", hint="run astrarium through `uv run arium ...`")
    return found


def run_uv(uv: str, args: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    """`uv <args>` isolated from operator's own uv.toml and resolution env.

    Root-owned /etc/uv/uv.toml is still read. Caller decides what non-zero returncode means.
    """

    with tempfile.TemporaryDirectory(prefix="astrarium-uv-config-") as config_dir:
        return subprocess.run(  # noqa: S603
            [uv, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            env=uv_env(os.environ, Path(config_dir)),
        )


def uv_add(uv: str, project: Path, package: str, version: str) -> None:
    """`uv add --no-sync <package>==<version>`: rewrites pyproject.toml and uv.lock, leaves running venv alone.

    Operator uv.toml (XDG locations) and resolution env settings never reach uv, root-owned /etc/uv/uv.toml does.
    """

    if not PIN_TEXT.fullmatch(version):
        raise UsageProblem(f"invalid version {version!r} for {package}")
    result = run_uv(
        uv,
        [
            "add",
            "--no-sync",
            f"{package}=={version}",
        ],
        project,
    )
    if result.returncode != 0:
        tail = " | ".join(result.stderr.strip().splitlines()[-3:])
        raise ExternalToolError(
            f"uv add {package}=={version} failed (exit {result.returncode})", hint=tail if tail else None
        )


def check_lock_bump(before: str, after: str, package: str, version: Version) -> str:
    """Package version in uv.lock text after `uv add`, ExternalToolError unless it is version with [options] kept."""

    try:
        old, new = tomllib.loads(before), tomllib.loads(after)
    except tomllib.TOMLDecodeError as e:
        raise ExternalToolError(f"uv.lock is not valid TOML after uv add: {e}") from None
    pinned = lock_versions(after).get(package, "")
    try:
        matches = Version(pinned) == version
    except InvalidVersion:
        matches = False
    if not matches:
        raise ExternalToolError(f"uv.lock pins {package} {pinned!r} after uv add, expected {version}")
    if new.get("options", {}) != old.get("options", {}):
        raise ExternalToolError(
            "uv add changed uv.lock [options]", hint="keep resolver settings in pyproject.toml [tool.uv]"
        )
    return pinned


def _restore(saved: Mapping[Path, bytes | None]) -> None:
    for path, data in saved.items():
        if data is None:
            path.unlink(missing_ok=True)
        else:
            path.write_bytes(data)


@dataclass(frozen=True)
class ApplyOptions:
    component: str | None
    changed_since: str | None
    limit: str | None
    canary: str | None
    canary_wait: float
    stagger: float
    identity: CastIdentity
    via: Via | None
    dry_run: bool
    allow_dirty: bool
    echo: Callable[[str], None] | None = None


@dataclass(frozen=True)
class ApplyPlan:
    title: str
    targets: list[str]
    skipped: dict[str, str]
    not_attempted: dict[str, str]
    stages: list[Stage]
    applied: dict[str, list[str]]


def applicable(registry: Mapping[str, Component], name: str) -> Component:
    """Component `versions apply` can cast: NullForge-owned with rune, UsageProblem otherwise."""

    component = registry.get(name)
    if component is None:
        raise UsageProblem(f"unknown component {name!r}", hint=f"known: {', '.join(sorted(registry))}")
    if component.owner == "astrarium":
        raise UsageProblem(f"{name} is converged by `arium fleet deploy`, not by versions apply")
    if component.owner == "tooling":
        raise UsageProblem(f"{name} belongs to the tool stack", hint=f"use `arium versions bump {name} VERSION`")
    if component.rune is None:
        raise UsageProblem(f"{name} has no apply path", hint="cast its rune with `arium fleet provision --rune NAME`")
    return component


def wanted_components(
    component: str | None,
    changes: PinChanges | None,
    registry: Mapping[str, Component],
) -> tuple[list[str], dict[str, list[str]] | None]:
    """Components to apply, plus per-node NullForge-owned changes for --changed-since."""

    if changes is None:
        if component is None:
            raise UsageProblem("give COMPONENT or --changed-since REF")
        return [component], None
    per_node = {
        node_id: [name for name in names if name in registry and registry[name].owner == "nullforge"]
        for node_id, names in changes.by_node.items()
    }
    return sorted({name for names in per_node.values() for name in names}), per_node


def plan_apply(
    nodes: Mapping[str, EffectiveNode],
    manifest: Manifest,
    registry: Mapping[str, Component],
    repo: Repo,
    *,
    components: Sequence[str],
    limit: str | None,
    identity: CastIdentity,
    per_node: Mapping[str, Sequence[str]] | None = None,
) -> ApplyPlan:
    """Targets, skipped and not attempted nodes, single rune stage of `versions apply`.

    per_node (--changed-since) never casts broad runes, nor bastions as ci: such nodes end not attempted.
    """

    checked = [applicable(registry, name) for name in components]
    selection = select(
        nodes,
        limit,
        hexrift_only=False,
    )
    named = set(parse_limit(limit))
    targets: list[str] = []
    skipped = dict(selection.skipped)
    not_attempted: dict[str, str] = {}
    stage: dict[str, tuple[str, ...]] = {}
    applied: dict[str, list[str]] = {}
    cast_runes: set[str] = set()
    for node_id in selection.nodes:
        node = nodes[node_id]
        wanted = [item for item in checked if per_node is None or item.name in per_node.get(node_id, [])]
        if not wanted:
            continue
        ready = [
            item
            for item in wanted
            if feature_enabled(node.features, item.feature)
            and pin_layer(
                manifest,
                item.name,
                node_id,
            )[0]
            is not None
        ]
        reason = bastion_skip(
            node,
            named,
            identity,
        )
        if reason is not None:
            if per_node is not None and identity == "ci" and ready:
                not_attempted[node_id] = f"bastion: apply from a laptop with --limit {node_id}"
            else:
                skipped[node_id] = reason
            continue
        if not ready:
            skipped[node_id] = f"{', '.join(item.name for item in wanted)} not enabled on this node"
            continue
        runes = sorted({item.rune for item in ready if item.rune is not None})
        if per_node is not None and any(rune in RUNE_NOTES for rune in runes):
            not_attempted[node_id] = f"broad rune: apply from a laptop ({', '.join(item.name for item in ready)})"
            continue
        targets.append(node_id)
        applied[node_id] = [item.name for item in ready]
        stage[node_id] = tuple(resolve_rune(rune, repo) for rune in runes)
        cast_runes.update(runes)
    if targets:
        check_targets(
            targets,
            nodes,
            manifest.control,
        )
    notes = [RUNE_NOTES[rune] for rune in sorted(cast_runes) if rune in RUNE_NOTES]
    title = f"versions apply {', '.join(components)}"
    if notes:
        title += f" ({'; '.join(notes)})"
    return ApplyPlan(
        title=title,
        targets=targets,
        skipped=skipped,
        not_attempted=not_attempted,
        stages=[stage] if targets else [],
        applied=applied,
    )


def pin_verifier(
    transport: Transport,
    manifest: Manifest,
    registry: Mapping[str, Component],
    applied: Mapping[str, Sequence[str]],
    masker: ValueMasker,
) -> Verifier:
    """Re-probe after each batch: every applied component installed at node's effective pin."""

    async def verify(batch: list[str]) -> dict[str, str]:
        wanted = {
            node_id: [registry[name] for name in applied.get(node_id, []) if registry[name].probe is not None]
            for node_id in batch
        }
        probes, failed_rc = await probe_nodes(
            transport,
            batch,
            wanted,
            masker,
        )
        failures: dict[str, str] = {}
        for node_id in batch:
            if not wanted[node_id]:
                continue
            found = probes.get(node_id)
            if found is None:
                failures[node_id] = f"version probe failed after cast (exit {failed_rc[node_id]})"
                continue
            problems: list[str] = []
            for component in wanted[node_id]:
                pin, _ = pin_layer(
                    manifest,
                    component.name,
                    node_id,
                )
                installed = found.get(component.name)
                if (
                    pin_matches(
                        component,
                        pin,
                        installed,
                    )
                    is not True
                ):
                    pinned = pin_label(pin) if pin is not None else "-"
                    shown = installed_label(component, installed)
                    problems.append(f"{component.name}: installed {shown}, pinned {pinned}")
            if problems:
                failures[node_id] = "; ".join(problems)
        return failures

    return verify


def note_unprobed(
    reports: Mapping[str, CastReport],
    applied: Mapping[str, Sequence[str]],
    registry: Mapping[str, Component],
) -> dict[str, CastReport]:
    """Done casts that applied components without probe carry reason `no probe`, never pass as re-probed."""

    noted = dict(reports)
    for node_id, names in applied.items():
        unprobed = [name for name in names if registry[name].probe is None]
        report = noted.get(node_id)
        if unprobed and report is not None and report.outcome.status in DONE:
            outcome = Outcome(report.outcome.status, f"no probe: {', '.join(unprobed)}")
            noted[node_id] = replace(report, outcome=outcome)
    return noted


async def status_versions(
    transport: Transport,
    nodes: Mapping[str, EffectiveNode],
    manifest: Manifest,
    lockfile: Path,
    node_ids: Sequence[str],
    *,
    all_components: bool,
    masker: ValueMasker,
) -> dict[str, list[VersionCell]]:
    """Versions part of `arium fleet status`: listed components against installed, probed as deploy user."""

    registry = build_registry(manifest, lockfile)
    names = listed_components(
        registry,
        manifest,
        all_components=all_components,
    )
    probes = await probe_versions(
        transport,
        nodes,
        registry,
        names,
        node_ids,
        identity="deploy",
        masker=masker,
    )
    return cells_for(
        nodes,
        manifest,
        registry,
        names,
        node_ids,
        probes,
    )


class VersionsController(BaseController["AstrariumApp"]):
    """Component versions: registry, probes, upstream releases, manifest and uv.lock edits, cast-based apply."""

    def make_upstream(self) -> Upstream:
        return UpstreamClient(self.app.repo.cache_dir, os.environ.get("GITHUB_TOKEN"))

    def make_transport(self, paths: SshPaths, jumped: frozenset[str]) -> Transport:
        return OpenSshTransport(
            paths,
            jumped=jumped,
            jump_limit=JUMP_CONCURRENCY,
        )

    def uv_binary(self) -> str:
        return find_uv()

    async def list_versions(self, opts: ListOptions) -> ListReport:
        """Rows of `versions list`: pins, layers, node pins, installed per node (read-only probe), latest upstream."""

        repo = self.app.repo
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            manifest, nodes = ctx.manifest, ctx.nodes
            if opts.node is not None and opts.node not in nodes:
                raise UsageProblem(f"unknown node {opts.node!r}")
            registry = build_registry(manifest, repo.lockfile)
            check_pins(manifest, registry)
            names = listed_components(
                registry,
                manifest,
                all_components=opts.all_components,
            )
            node_ids = [opts.node] if opts.node is not None else sorted(nodes)
            probes: Probes = {}
            if opts.probe:
                control = manifest.control
                via = resolve_via(control, opts.via)
                probed_ids = [
                    node_id
                    for node_id in node_ids
                    if nodes[node_id].root_role != "bastion" and nodes[node_id].host_keys
                ]
                paths, jumped = write_scoped_ssh(
                    runtime,
                    nodes,
                    control,
                    "deploy",
                    via,
                    wanted=probed_ids,
                )
                transport = self.make_transport(paths, jumped)
                probes = await probe_versions(
                    transport,
                    nodes,
                    registry,
                    names,
                    probed_ids,
                    identity="deploy",
                    masker=ctx.masker,
                )
            cells = cells_for(
                nodes,
                manifest,
                registry,
                names,
                node_ids,
                probes,
            )
        latest = latest_versions(
            registry,
            names,
            manifest,
            self.make_upstream(),
            pre=False,
        )
        rows = component_rows(
            manifest,
            registry,
            names,
            tool_stack_versions(repo.lockfile),
            latest,
            cells,
        )
        return ListReport(
            node=opts.node, probed=opts.probe, rows=rows, warnings=[*lookup_warnings(latest), *mapping_warnings()]
        )

    def outdated(self, *, pre: bool, all_components: bool) -> OutdatedReport:
        """Pins behind upstream, from plaintext astrarium.yaml and uv.lock (no sops identity needed)."""

        repo = self.app.repo
        manifest = load_manifest(repo, None)
        registry = build_registry(manifest, repo.lockfile)
        check_pins(manifest, registry)
        names = listed_components(
            registry,
            manifest,
            all_components=all_components,
        )
        latest = latest_versions(
            registry,
            names,
            manifest,
            self.make_upstream(),
            pre=pre,
        )
        rows = outdated_rows(
            manifest,
            registry,
            names,
            tool_stack_versions(repo.lockfile),
            latest,
        )
        return OutdatedReport(
            pre=pre,
            rows=rows,
            warnings=[*lookup_warnings(latest), *mapping_warnings()],
        )

    def bump(self, opts: BumpOptions) -> BumpResult:
        """Pin component to version after upstream checks, manifest edits keep comments."""

        repo = self.app.repo
        manifest = load_manifest(repo, None)
        registry = build_registry(manifest, repo.lockfile)
        component = registry.get(opts.component)
        if component is None:
            raise UsageProblem(f"unknown component {opts.component!r}", hint=f"known: {', '.join(sorted(registry))}")
        if opts.node is not None and opts.node not in manifest.nodes:
            raise UsageProblem(f"unknown node {opts.node!r}")
        if component.owner == "tooling":
            return self._bump_tool(component, opts)
        previous, _ = pin_layer(
            manifest,
            component.name,
            opts.node,
        )
        upstream = self.make_upstream()
        if component.owner == "astrarium":
            with RuntimeDir() as runtime:
                pin = xray_pin(
                    opts.version,
                    fleet_archs(manifest, opts.node),
                    upstream,
                    runtime.sub("xray-assets"),
                )
        else:
            pin = nullforge_pin(
                component,
                opts.version,
                upstream,
            )
        editor = ManifestEditor(repo.manifest)
        editor.set_version(
            component.name,
            pin,
            opts.node,
        )
        editor.save()
        before = pin_label(previous) if previous is not None else None
        return BumpResult(
            component=component.name,
            node=opts.node,
            before=before,
            after=pin_label(pin),
            files=["astrarium.yaml"],
        )

    def _bump_tool(self, component: Component, opts: BumpOptions) -> BumpResult:
        if opts.node is not None:
            raise UsageProblem("tool stack versions are fleet-wide", hint="drop --node")
        try:
            wanted = Version(opts.version)
        except InvalidVersion:
            raise UsageProblem(f"invalid version {opts.version!r} for {component.name}") from None
        repo = self.app.repo
        uv = self.uv_binary()
        saved = {path: path.read_bytes() if path.is_file() else None for path in (repo.pyproject, repo.lockfile)}
        before_lock = repo.lockfile.read_text(encoding="utf-8")
        before = lock_versions(before_lock).get(component.name)
        try:
            uv_add(
                uv,
                repo.root,
                component.name,
                opts.version,
            )
            after = check_lock_bump(
                before_lock,
                repo.lockfile.read_text(encoding="utf-8"),
                component.name,
                wanted,
            )
        except BaseException:
            _restore(saved)
            raise
        return BumpResult(
            component=component.name,
            node=None,
            before=before,
            after=after,
            files=["pyproject.toml", "uv.lock"],
        )

    async def apply(
        self,
        opts: ApplyOptions,
        confirm: Callable[[list[CastPreview]], bool],
    ) -> dict[str, CastReport] | None:
        """Cast runes of NullForge pins where enabled, then re-probe, None when confirmation is declined."""

        if (opts.component is None) == (opts.changed_since is None):
            raise UsageProblem("give either COMPONENT or --changed-since REF")
        repo = self.app.repo
        ensure_clean(repo, allow_dirty=opts.allow_dirty or opts.dry_run)
        changes = changed_since(repo, opts.changed_since) if opts.changed_since is not None else None
        reports: dict[str, CastReport] = {}
        if changes is not None:
            new_since = Outcome(Status.SKIPPED, "new since base: run arium fleet provision")
            reports.update({node_id: CastReport(new_since) for node_id in changes.new_nodes})
            if not changes.by_node:
                return reports
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            manifest, nodes = ctx.manifest, ctx.nodes
            control = manifest.control
            via = resolve_via(control, opts.via)
            check_cast_identity(
                opts.identity,
                via,
                control,
            )
            registry = build_registry(manifest, repo.lockfile)
            check_pins(manifest, registry)
            components, per_node = wanted_components(
                opts.component,
                changes,
                registry,
            )
            if not components:
                return reports
            plan = plan_apply(
                nodes,
                manifest,
                registry,
                repo,
                components=components,
                limit=opts.limit,
                identity=opts.identity,
                per_node=per_node,
            )
            reports.update({node_id: CastReport(Outcome(Status.SKIPPED, why)) for node_id, why in plan.skipped.items()})
            reports.update(
                {node_id: CastReport(Outcome(Status.NOT_ATTEMPTED, why)) for node_id, why in plan.not_attempted.items()}
            )
            if not plan.targets:
                return reports
            schedule = build_schedule(
                Selection(nodes=plan.targets, skipped={}),
                nodes,
                opts.canary,
                control.jump,
            )
            cast_plan = CastPlan(
                batches=cast_batches(schedule),
                stages=plan.stages,
                identity=opts.identity,
                via=via,
                canary=opts.canary,
                canary_wait=opts.canary_wait,
                stagger=opts.stagger,
                dry=opts.dry_run,
            )
            if not confirm(
                [
                    preview_of(
                        plan.title,
                        cast_plan,
                        {**plan.skipped, **plan.not_attempted},
                    )
                ]
            ):
                return None

            def make_verify(transport: Transport) -> Verifier:
                return pin_verifier(
                    transport,
                    manifest,
                    registry,
                    plan.applied,
                    ctx.masker,
                )

            casts = await self.app.inventory.run_casts(
                runtime,
                nodes,
                control,
                cast_plan,
                ctx.masker,
                verify=make_verify,
                echo=opts.echo,
            )
            reports.update(
                casts
                if opts.dry_run
                else note_unprobed(
                    casts,
                    plan.applied,
                    registry,
                )
            )
            log_cast_run(
                repo,
                "versions-apply",
                reports,
                ctx.masker,
            )
        return reports
