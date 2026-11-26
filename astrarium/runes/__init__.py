"""Astrarium runes: pyinfra deploy files passed to `nullforge cast -r` by absolute path."""

from importlib.resources import files
from typing import Final


BUILTIN_RUNES: Final[tuple[str, ...]] = ("deploy_access", "ci_access")


def builtin_rune_path(name: str) -> str:
    return str(files("astrarium.runes") / f"{name}.py")
