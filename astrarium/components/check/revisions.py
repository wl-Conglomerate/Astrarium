"""Git access to base revision for `check`."""

from __future__ import annotations

import io
import logging
import os
import subprocess
from pathlib import Path

from astrarium.components.versions.changes import resolve_commit
from astrarium.errors import ExternalToolError, Refused, UsageProblem


LOG = logging.getLogger(__name__)

REVISION_PATHS = (
    "astrarium.yaml",
    "topology.yaml",
    "uv.lock",
    ".sops.yaml",
    "secrets",
)
"""Paths materialized for base builds and secrets report."""

CODE_PATHS = ("runes", ".github")
"""Paths whose raw diff goes into report."""


def code_diff(root: Path, sha: str) -> str:
    return _git(
        root,
        "diff",
        "--no-color",
        sha,
        "--",
        *CODE_PATHS,
    ).decode(errors="replace")


def _git(root: Path, *args: str) -> bytes:
    """Run git in root, raise ExternalToolError on failure."""

    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(root),
            *args,
        ],
        capture_output=True,
        check=False,
    )  # noqa: S603, S607
    if proc.returncode != 0:
        raise ExternalToolError(f"git {' '.join(args)} failed: {proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def resolve_base(root: Path, ref: str) -> str:
    """Merge-base sha of `ref` and HEAD, so commits only on base never show as reverted.

    UsageProblem, not resolve_commit's Refused: unresolvable --base is bad command
    argument here, not safety refusal.
    """

    try:
        commit = resolve_commit(root, ref)
    except Refused as e:
        raise UsageProblem(e.message, hint=e.hint) from e
    argv = [
        "git",
        "-C",
        str(root),
        "merge-base",
        commit,
        "HEAD",
    ]
    proc = subprocess.run(  # noqa: S603
        argv,
        capture_output=True,
        text=True,
        check=False,
    )  # noqa: S603, S607
    if proc.returncode != 0:
        if proc.stderr.strip():
            LOG.warning(
                f"git merge-base {commit[:12]} HEAD: {proc.stderr.strip()}",
            )
        raise UsageProblem(f"{ref} and HEAD share no history in this clone", hint="CI checkouts need fetch-depth: 0")
    return proc.stdout.strip()


def head_label(root: Path) -> str:
    """Short HEAD sha, `+dirty` when tracked files differ from it."""

    sha = (
        _git(
            root,
            "rev-parse",
            "--short=12",
            "HEAD",
        )
        .decode()
        .strip()
    )
    dirty = (
        _git(
            root,
            "status",
            "--porcelain",
            "--untracked-files=no",
        )
        .decode()
        .strip()
    )
    return f"{sha}+dirty" if dirty else sha


def _blobs(root: Path, sha: str, paths: tuple[str, ...]) -> dict[str, str]:
    # ls-tree filters and names relative to cwd: works for root nested inside bigger worktree
    found: dict[str, str] = {}
    for entry in _git(
        root,
        "ls-tree",
        "-r",
        "-z",
        sha,
        "--",
        *paths,
    ).split(b"\0"):
        meta, _, name = entry.partition(b"\t")
        fields = meta.split()
        if len(fields) == 3 and fields[1] == b"blob":
            found[os.fsdecode(name)] = fields[2].decode()
    return found


def materialize_revision(root: Path, sha: str, dest: Path) -> Path:
    """Write REVISION_PATHS files of commit `sha` under `dest` byte for byte, absent paths skipped.

    One `git ls-tree` plus one `git cat-file --batch`, instead of one `cat-file blob` per file.
    """

    dest.mkdir(parents=True, exist_ok=True)
    blobs = _blobs(
        root,
        sha,
        REVISION_PATHS,
    )
    order = sorted(blobs.items())
    if not order:
        return dest
    proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "-C",
            str(root),
            "cat-file",
            "--batch",
        ],  # noqa: S607
        input="".join(f"{blob}\n" for _, blob in order).encode(),
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise ExternalToolError(f"git cat-file --batch failed: {proc.stderr.decode(errors='replace').strip()}")
    stream = io.BytesIO(proc.stdout)
    for rel, _blob in order:
        header = stream.readline().split()
        size = int(header[2])
        content = stream.read(size)
        stream.read(1)  # trailing newline after blob content
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    return dest
