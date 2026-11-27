"""NullForge pin changes since base commit, for `arium versions apply --changed-since`."""

from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nullforge.smithy.versions import DEFAULT_VERSIONS

from astrarium.components.manifest.loader import parse_raw, read_raw
from astrarium.components.versions.registry import TOOL_STACK, XRAY, lock_versions
from astrarium.errors import Refused
from astrarium.repo import Repo


ZERO_REF = re.compile(r"^0+$")

MANIFEST_FILE = "astrarium.yaml"

LOCK_FILE = "uv.lock"

logger = logging.getLogger(__name__)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(root),
            *args,
        ],
        capture_output=True,
        text=True,
        check=False,
    )  # noqa: S603, S607


def nullforge_owned(raw: Mapping[str, Any]) -> set[str]:
    return (set(DEFAULT_VERSIONS) | set(_section(raw, "components"))) - {XRAY.name, *TOOL_STACK}


@dataclass(frozen=True)
class PinChanges:
    base: str
    by_node: dict[str, list[str]]
    new_nodes: list[str]


def check_ref(ref: str) -> str:
    """Base ref usable as commit, fails closed on empty, all-zero and option-like refs."""

    text = ref.strip()
    if not text or ZERO_REF.fullmatch(text) or text.startswith("-"):
        raise Refused(
            f"--changed-since needs a base commit, got {ref!r}",
            hint="a push that creates a branch has no base: apply components by name instead",
        )
    return text


def resolve_commit(root: Path, ref: str) -> str:
    """Full commit sha of ref. Refused when clone lacks it."""

    result = _git(
        root,
        "rev-parse",
        "--verify",
        "--quiet",
        f"{ref}^{{commit}}",
    )
    if result.returncode != 0:
        if result.stderr.strip():
            logger.warning(
                f"git rev-parse {ref}: {result.stderr.strip()}",
            )
        raise Refused(f"{ref!r} is not a commit in this clone", hint="CI checkouts need fetch-depth: 0")
    return result.stdout.strip()


def file_at(root: Path, commit: str, path: str) -> str | None:
    """Content of repo file at commit, path taken relative to root itself, not worktree toplevel.

    None when absent there (git show exit 128, no error worth keeping). Leading `./` is load-bearing:
    without it git resolves `path` against worktree toplevel, which breaks when `root` is deployment
    repo nested inside bigger worktree (see Repo._toplevel_prefix for matching case in dirty_paths).
    """

    result = _git(
        root,
        "show",
        f"{commit}:./{path}",
    )
    return result.stdout if result.returncode == 0 else None


def _section(data: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = data.get(key, {})
    return value if isinstance(value, Mapping) else {}


def node_pins(raw: Mapping[str, Any], node_id: str, defaults: Mapping[str, str]) -> dict[str, Any]:
    """Effective pins of node in raw manifest: defaults < versions < node overrides."""

    node = _section(_section(raw, "nodes"), node_id)
    return {
        **defaults,
        **_section(raw, "versions"),
        **_section(_section(node, "overrides"), "versions"),
    }


def pin_changes(
    base_raw: Mapping[str, Any],
    head_raw: Mapping[str, Any],
    defaults: Mapping[str, str],
) -> tuple[dict[str, list[str]], list[str]]:
    """Components whose effective pin differs, per node present at both revisions, nodes new in head."""

    base_nodes = _section(base_raw, "nodes")
    head_nodes = _section(head_raw, "nodes")
    changed: dict[str, list[str]] = {}
    for node_id in sorted(set(base_nodes) & set(head_nodes)):
        before = node_pins(
            base_raw,
            node_id,
            defaults,
        )
        after = node_pins(
            head_raw,
            node_id,
            defaults,
        )
        names = sorted(name for name in set(before) | set(after) if before.get(name) != after.get(name))
        if names:
            changed[node_id] = names
    return changed, sorted(set(head_nodes) - set(base_nodes))


def changed_since(repo: Repo, ref: str) -> PinChanges:
    """NullForge-owned pin changes between ref and working tree.

    Refused when base is unusable or NullForge itself changed.
    """

    commit = resolve_commit(repo.root, check_ref(ref))
    base_text = file_at(
        repo.root,
        commit,
        MANIFEST_FILE,
    )
    if base_text is None:
        raise Refused(f"{MANIFEST_FILE} does not exist at {commit[:12]}")
    base_lock = file_at(
        repo.root,
        commit,
        LOCK_FILE,
    )
    head_lock = repo.lockfile.read_text(encoding="utf-8") if repo.lockfile.is_file() else None
    before = lock_versions(base_lock).get("nullforge") if base_lock is not None else None
    after = lock_versions(head_lock).get("nullforge") if head_lock is not None else None
    if before != after:
        raise Refused(
            f"NullForge changed since {commit[:12]} ({before} -> {after}): its default pins cannot be compared",
            hint=(
                "review with `arium fleet provision --dry-run`, apply from a laptop,"
                " then dispatch versions-apply with since=<bump commit>"
            ),
        )
    base_raw = parse_raw(base_text, f"{MANIFEST_FILE} at base commit")
    head_raw = read_raw(repo.manifest)
    changed, new_nodes = pin_changes(
        base_raw,
        head_raw,
        DEFAULT_VERSIONS,
    )
    owned = nullforge_owned(head_raw)
    kept = {node_id: [name for name in names if name in owned] for node_id, names in changed.items()}
    by_node = {node_id: names for node_id, names in kept.items() if names}
    return PinChanges(
        base=commit,
        by_node=by_node,
        new_nodes=new_nodes,
    )
