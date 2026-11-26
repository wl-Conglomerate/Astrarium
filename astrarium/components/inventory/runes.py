"""Rune arguments for `nullforge cast -r`: astrarium built-ins, deployment runes/, NullForge names."""

from __future__ import annotations

import re

from nullforge.runes import discover_runes

from astrarium.components.manifest.models import RUNE_NAME_PATTERN
from astrarium.errors import InvalidManifest, UsageProblem
from astrarium.repo import Repo
from astrarium.runes import BUILTIN_RUNES, builtin_rune_path


RUNE_NAME = re.compile(RUNE_NAME_PATTERN)


def repo_runes(repo: Repo) -> list[str]:
    """Rune names in deployment runes/ (files starting with _ are helpers, not runes)."""

    if not repo.runes_dir.is_dir():
        return []
    names = sorted(path.stem for path in repo.runes_dir.glob("*.py") if not path.name.startswith("_"))
    reserved = set(BUILTIN_RUNES) | {info.name for info in discover_runes()}
    bad = [name for name in names if not RUNE_NAME.fullmatch(name) or name in reserved]
    if bad:
        raise InvalidManifest(
            f"runes/ files with unusable names: {', '.join(bad)}",
            hint=f"name runes lowercase, starting with a letter, other than {', '.join(sorted(reserved))}",
        )
    return names


def resolve_rune(name: str, repo: Repo) -> str:
    """Absolute path for astrarium built-in or runes/<name>.py, else NullForge built-in name."""

    if not RUNE_NAME.fullmatch(name):
        raise UsageProblem(f"invalid rune name {name!r}", hint="give a bare rune name such as telemt")
    if name in BUILTIN_RUNES:
        return builtin_rune_path(name)
    known = sorted(info.name for info in discover_runes())
    local = repo.runes_dir / f"{name}.py"
    if local.is_file():
        if name in known:
            raise InvalidManifest(
                f"runes/{name}.py shadows the NullForge rune {name!r}",
                hint=f"rename runes/{name}.py; NullForge runes: {', '.join(known)}",
            )
        return str(local.resolve())
    if name in known:
        return name
    raise UsageProblem(
        f"unknown rune {name!r}",
        hint=f"NullForge runes: {', '.join(known)}; astrarium runes: {', '.join(BUILTIN_RUNES)}",
    )
