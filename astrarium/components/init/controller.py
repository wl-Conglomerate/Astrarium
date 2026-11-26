"""`init`: render bundled template, lock tool stack, write encrypted overlay.

Template ships inside package, so rendered repo always matches running Astrarium version and
no repository URL lives in code. Copier never runs its own tasks (`skip_tasks=True` always). Deployment repo's
`uv lock` runs from here, isolated from operator's own uv config, so `init` behaves same whether or not that
config sets private index. `unsafe=True` goes to trusted bundled template only. Custom `--template` needs `--trust`.
Copier is imported on first use, so other commands never pay its import time.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Generator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version
from importlib.resources import as_file, files
from pathlib import Path
from typing import TYPE_CHECKING, Any

from astrarium import __version__
from astrarium.components.check.throwaway import random_namespace
from astrarium.components.secrets.recipients import normalize_recipient
from astrarium.components.versions.controller import find_uv, run_uv
from astrarium.core.controller import BaseController
from astrarium.errors import ExternalToolError, UsageProblem


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp

OVERLAY_PATH = Path("secrets") / "astrarium.sops.yaml"

PHOTON_HINT = "`uv lock` needs photon credentials: UV_INDEX_PHOTON_USERNAME=__token__ and UV_INDEX_PHOTON_PASSWORD"


def tool_versions() -> dict[str, str]:
    """`==` pins for new repo: running Astrarium and HexRift/NullForge (and Manticora when installed)."""

    found = {
        "astrarium_version": __version__,
        "hexrift_version": version("hexrift"),
        "nullforge_version": version("nullforge"),
    }
    with suppress(PackageNotFoundError):
        found["manticora_version"] = version("manticora")
    return found


def _normalize_recipients(value: str) -> str:
    lines = [line for line in value.splitlines() if line.strip()]
    return "\n".join(normalize_recipient(line) for line in lines)


def _run_uv_lock(dest: Path) -> None:
    result = run_uv(
        find_uv(),
        ["lock"],
        dest,
    )
    if result.returncode != 0:
        tail = " | ".join(result.stderr.strip().splitlines()[-3:])
        message = f"uv lock failed (exit {result.returncode})" + (f": {tail}" if tail else "")
        raise ExternalToolError(message, hint=PHOTON_HINT)


@dataclass(frozen=True)
class InitOptions:
    """Inputs of one `arium repo init`."""

    dest: Path
    answers: Mapping[str, Any] = field(default_factory=dict)
    template: str | None = None
    """Copier template source, None renders bundled template, git URL or local path needs `trust`."""
    vcs_ref: str | None = None
    """Git ref of external `template`, ignored for bundled template."""
    defaults: bool = False
    run_tasks: bool = True
    quiet: bool = False
    trust: bool = False


@dataclass(frozen=True)
class InitResult:
    """Created repo, its files (relative paths), DNS answer and whether `uv lock` ran."""

    dest: Path
    files: list[str]
    has_dns: bool
    locked: bool


@contextmanager
def bundled_template() -> Generator[str]:
    """Bundled template root as filesystem path (Copier renders only from real directories)."""

    with as_file(files("astrarium._template")) as path:
        yield str(path)


def _copy(opts: InitOptions, data: Mapping[str, Any]) -> bool:
    """Copier copy into `opts.dest`, return DNS answer. Copier errors and rejected answers raise UsageProblem."""

    from copier import run_copy
    from copier.errors import CopierError

    try:
        if opts.template is None:
            with bundled_template() as source:
                worker = run_copy(
                    source,
                    opts.dest,
                    data=dict(data),
                    defaults=opts.defaults,
                    quiet=opts.quiet,
                    unsafe=True,
                    skip_tasks=True,
                )
        else:
            worker = run_copy(
                opts.template,
                opts.dest,
                data=dict(data),
                vcs_ref=opts.vcs_ref,
                defaults=opts.defaults,
                quiet=opts.quiet,
                unsafe=opts.trust,
                skip_tasks=True,
            )
    except (CopierError, ValueError) as e:
        raise UsageProblem(str(e)) from e
    return bool(worker.answers.combined.get("has_dns", False))


class InitController(BaseController["AstrariumApp"]):
    """Deployment repo creation."""

    def init(self, opts: InitOptions) -> InitResult:
        """Copier copy into empty `dest`, isolated `uv lock`, then encrypted overlay with fresh namespace.

        Any failure once rendering starts (Ctrl-C included) removes `dest` when this call created it.
        Pre-existing empty directory stays.
        """

        if opts.dest.exists() and any(opts.dest.iterdir()):
            raise UsageProblem(
                f"{opts.dest} is not empty", hint="init creates new repo: pick empty or missing directory"
            )
        if not opts.defaults and not sys.stdin.isatty():
            raise UsageProblem(
                "init needs a terminal to answer template questions",
                hint="run in a terminal, or pass --defaults with --name, --domain, --photon-url and --recipient",
            )
        data = {**tool_versions(), **opts.answers}
        if data.get("age_recipients"):
            data["age_recipients"] = _normalize_recipients(str(data["age_recipients"]))
        if data.get("has_dns") is True and not data.get("manticora_version"):
            raise UsageProblem("DNS needs Manticora version to pin", hint="pass --manticora-version")
        created = not opts.dest.exists()
        try:
            has_dns = _copy(opts, data)
            if opts.run_tasks:
                _run_uv_lock(opts.dest)
            self._write_overlay(opts.dest)
        except BaseException:
            if created:
                shutil.rmtree(opts.dest, ignore_errors=True)
            raise
        files = sorted(
            str(path.relative_to(opts.dest))
            for path in opts.dest.rglob("*")
            if path.is_file() and ".git" not in path.parts and ".venv" not in path.parts
        )
        return InitResult(
            dest=opts.dest,
            files=files,
            has_dns=has_dns,
            locked=opts.run_tasks,
        )

    def _write_overlay(self, dest: Path) -> None:
        """Overlay written straight to disk: namespace never passes through Copier or its answers file."""

        plaintext = f"topology:\n  namespace: {random_namespace()}\n".encode()
        encrypted = self.app.sops.encrypt(
            plaintext,
            filename_override=OVERLAY_PATH,
            cwd=dest,
        )
        target = dest / OVERLAY_PATH
        target.parent.mkdir(parents=True, exist_ok=True)
        partial = target.with_name(f".{target.name}.partial")
        partial.write_bytes(encrypted)
        partial.replace(target)
