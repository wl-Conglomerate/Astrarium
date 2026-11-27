"""Per-node plan: what changes, masked diff, prerequisites."""

from __future__ import annotations

import difflib
import json
import logging
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import Arch, VersionPin
from astrarium.components.rollout.artifacts import XrayArtifact, head_commit, sha256_file
from astrarium.components.rollout.outcomes import PREREQUISITE, Outcome, Status
from astrarium.components.rollout.probe import LiveState
from astrarium.components.secrets.masking import ValueMasker, mask_haproxy, mask_structure
from astrarium.components.topology.bridge import BuiltNode


LOG = logging.getLogger(__name__)

ARCH_MISMATCH = Outcome(Status.FAILED, "arch mismatch")

HAPROXY_NOT_INSTALLED = Outcome(Status.FAILED, "haproxy wanted but not installed")


def haproxy_installed(node: EffectiveNode) -> bool:
    return bool(node.features.get("haproxy", {}).get("install", False))


@dataclass(frozen=True)
class NodePlan:
    node_id: str
    before: LiveState
    config: Path | None
    haproxy: Path | None
    binary: XrayArtifact | None
    haproxy_installed: bool
    haproxy_wanted: bool
    diff: str


def artifact_required(pin: VersionPin | None, live: LiveState, arch: Arch, provided: Collection[Arch]) -> bool:
    """Release pins always compare binaries, main@sha pins only when build differs or artifact is given.

    --force alone never needs main@sha artifact: live binary stays, config files are forced.
    """

    if pin is None:
        return False
    commit = head_commit(pin)
    return commit is None or live.xray_build != commit or arch in provided


def _masked(label: str, text: str, masker: ValueMasker, kind: Literal["json", "haproxy"]) -> str:
    if kind == "json":
        try:
            text = json.dumps(mask_structure(json.loads(text)), indent=2) + "\n"
        except json.JSONDecodeError as e:
            LOG.warning(
                f"{label} is not valid JSON, hiding diff content: {e}",
            )
            return "<not valid JSON; content hidden>\n"
    else:
        text = mask_haproxy(text)
    return masker.mask(text)


def masked_diff(label: str, old: str | None, new: str, masker: ValueMasker, *, kind: Literal["json", "haproxy"]) -> str:
    """Unified diff with both sides masked by key/directive and by known value."""

    before = (
        _masked(
            f"live/{label}",
            old,
            masker,
            kind,
        )
        if old is not None
        else ""
    )
    after = _masked(
        f"new/{label}",
        new,
        masker,
        kind,
    )
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            f"live/{label}",
            f"new/{label}",
        )
    )


def _binary_differs(node: EffectiveNode, live: LiveState, artifact: XrayArtifact, force: bool) -> bool:
    if force:
        return True
    commit = head_commit(node.versions["xray"])
    if commit is not None:
        return live.xray_build != commit
    return live.xray_sha != artifact.sha256


def plan_node(
    node: EffectiveNode,
    built: BuiltNode,
    live: LiveState,
    artifact: XrayArtifact | None,
    *,
    force: bool,
    masker: ValueMasker,
    live_config_text: str | None,
) -> NodePlan | Outcome:
    """NodePlan when anything changes (or force), else UNCHANGED or FAILED (prerequisite, arch, HAProxy)."""

    if live.xray_sha is None:
        return PREREQUISITE
    if live.arch is not None and live.arch != node.arch:
        return ARCH_MISMATCH
    installed = haproxy_installed(node)
    if built.haproxy_wanted and not installed:
        return HAPROXY_NOT_INSTALLED
    new_config = sha256_file(built.config_json)
    config = built.config_json if force or live.config_sha != new_config else None
    haproxy = None
    if installed and (force or live.haproxy_sha != sha256_file(built.haproxy_cfg)):
        haproxy = built.haproxy_cfg
    binary = (
        artifact
        if artifact is not None
        and _binary_differs(
            node,
            live,
            artifact,
            force,
        )
        else None
    )
    if config is None and haproxy is None and binary is None:
        return Outcome(Status.UNCHANGED)
    diff = ""
    if live.config_sha != new_config:
        diff = masked_diff(
            "config.json",
            live_config_text,
            built.config_json.read_text(),
            masker,
            kind="json",
        )
    return NodePlan(
        node_id=node.id,
        before=live,
        config=config,
        haproxy=haproxy,
        binary=binary,
        haproxy_installed=installed,
        haproxy_wanted=built.haproxy_wanted,
        diff=diff,
    )
