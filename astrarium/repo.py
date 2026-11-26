"""Deployment repo paths, discovery and dirty-tree guard."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from astrarium.errors import ExternalToolError, InvalidManifest, Refused


MANIFEST_NAME = "astrarium.yaml"

GUARDED_PATHS = (
    "astrarium.yaml",
    "topology.yaml",
    "pyproject.toml",
    "uv.lock",
    "secrets",
    "runes",
)
"""Paths whose uncommitted changes block mutating commands unless --allow-dirty."""

_PREFIX_CACHE: dict[Path, str] = {}
"""git worktree toplevel prefix per repo root, `git status` prints toplevel-relative paths."""


@dataclass(frozen=True)
class Repo:
    """One deployment repo rooted at directory holding astrarium.yaml."""

    root: Path

    @property
    def manifest(self) -> Path:
        return self.root / MANIFEST_NAME

    @property
    def topology(self) -> Path:
        return self.root / "topology.yaml"

    @property
    def secrets_dir(self) -> Path:
        return self.root / "secrets"

    @property
    def overlay(self) -> Path:
        return self.secrets_dir / "astrarium.sops.yaml"

    @property
    def keys_dir(self) -> Path:
        return self.secrets_dir / "keys"

    @property
    def sops_config(self) -> Path:
        return self.root / ".sops.yaml"

    @property
    def dns_dir(self) -> Path:
        return self.root / "dns"

    @property
    def runes_dir(self) -> Path:
        return self.root / "runes"

    @property
    def workflows_dir(self) -> Path:
        return self.root / ".github" / "workflows"

    @property
    def pyproject(self) -> Path:
        return self.root / "pyproject.toml"

    @property
    def lockfile(self) -> Path:
        return self.root / "uv.lock"

    @property
    def state_dir(self) -> Path:
        return self.root / ".astrarium"

    @property
    def runs_dir(self) -> Path:
        return self.state_dir / "runs"

    @property
    def cache_dir(self) -> Path:
        return self.state_dir / "cache"

    @classmethod
    def discover(cls, start: Path | None = None) -> Repo:
        """Nearest ancestor of `start` (default cwd) holding astrarium.yaml."""

        origin = (start if start is not None else Path.cwd()).resolve()
        for directory in (origin, *origin.parents):
            if (directory / MANIFEST_NAME).is_file():
                return cls(root=directory)
        raise InvalidManifest(
            f"no {MANIFEST_NAME} in {origin} or any parent directory",
            hint="run inside a deployment repo or pass --repo PATH",
        )

    def key_file(self, node_id: str) -> Path:
        """Encrypted HexRift key file of node."""

        if Path(node_id).name != node_id or node_id in {
            "",
            ".",
            "..",
        }:
            raise InvalidManifest(f"invalid node id {node_id!r}")
        return self.keys_dir / f"{node_id}.yaml"

    def _git(self, *args: str, text: bool = False) -> subprocess.CompletedProcess[str]:
        """`git -C root args`, ExternalToolError when git is missing or exits non-zero."""

        try:
            proc = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "git",
                    "-C",
                    str(self.root),
                    *args,
                ],  # noqa: S607
                capture_output=True,
                text=text,
                check=False,
            )
        except OSError as e:
            raise ExternalToolError(
                f"git not found: {e}",
                hint="install git and ensure it is on PATH",
            ) from e
        if proc.returncode != 0:
            detail = proc.stderr if text else proc.stderr.decode(errors="replace")
            raise ExternalToolError(
                f"git {' '.join(args)} failed in {self.root}: {detail.strip()}",
                hint="deployment repos are git repositories: run `git init` or pass --repo",
            )
        return proc

    def dirty_paths(self) -> list[str]:
        """Guarded paths with uncommitted changes, untracked files included, relative to root."""

        proc = self._git(
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            *GUARDED_PATHS,
            text=True,
        )
        prefix = _toplevel_prefix(self.root)
        paths: list[str] = []
        entries = iter(proc.stdout.split("\0"))
        for entry in entries:
            if not entry:
                continue
            status, path = entry[:2], entry[3:]
            if prefix and path.startswith(prefix):
                path = path[len(prefix) :]
            paths.append(path)
            if "R" in status or "C" in status:
                next(entries, None)
        return sorted(set(paths))

    def commit(self) -> str | None:
        """HEAD commit sha, None without commits or without git on PATH."""

        try:
            proc = self._git(
                "rev-parse",
                "--verify",
                "--quiet",
                "HEAD",
                text=True,
            )
        except ExternalToolError:
            return None
        return proc.stdout.strip() or None


def _toplevel_prefix(root: Path) -> str:
    """Path of root relative to git worktree toplevel, e.g. 'deploy/', '' at toplevel. Cached per root."""

    if root not in _PREFIX_CACHE:
        try:
            proc = subprocess.run(  # noqa: S603
                [  # noqa: S607
                    "git",
                    "-C",
                    str(root),
                    "rev-parse",
                    "--show-prefix",
                ],  # noqa: S607
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as e:
            raise ExternalToolError(
                f"git not found: {e}",
                hint="install git and ensure it is on PATH",
            ) from e
        if proc.returncode != 0:
            raise ExternalToolError(
                f"git rev-parse failed in {root}: {proc.stderr.strip()}",
                hint="deployment repos are git repositories: run `git init` or pass --repo",
            )
        _PREFIX_CACHE[root] = proc.stdout.strip()
    return _PREFIX_CACHE[root]


def ensure_clean(repo: Repo, *, allow_dirty: bool) -> None:
    """Refused (exit 4) when guarded paths hold uncommitted changes, no git call when allowed."""

    if allow_dirty:
        return
    dirty = repo.dirty_paths()
    if dirty:
        raise Refused(
            f"uncommitted changes in {', '.join(dirty)}",
            hint="commit them first, or pass --allow-dirty",
        )
