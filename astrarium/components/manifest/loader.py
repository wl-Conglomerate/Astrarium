"""Manifest loading: plaintext YAML plus decrypted overlay -> validated Manifest."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from astrarium.components.manifest.models import Manifest
from astrarium.components.manifest.overlay import merge_overlay, validate_overlay
from astrarium.errors import InvalidManifest
from astrarium.repo import Repo


def parse_raw(text: str, source: str) -> dict[str, Any]:
    """YAML mapping from `text`, InvalidManifest (naming `source`) on broken YAML or non-mapping top level."""

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(
            e,
            "problem_mark",
            None,
        )
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark is not None else ""
        raise InvalidManifest(f"{source}: invalid YAML{where}") from None
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise InvalidManifest(f"{source}: top level must be a mapping")
    return data


def read_raw(path: Path) -> dict[str, Any]:
    """YAML mapping at `path`, InvalidManifest when missing, unreadable or not mapping."""

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as e:
        raise InvalidManifest(f"{path} not found") from e
    except (OSError, UnicodeDecodeError) as e:
        raise InvalidManifest(f"{path}: cannot read ({type(e).__name__})") from e
    return parse_raw(text, str(path))


def validation_lines(e: ValidationError, prefix: str = "") -> list[str]:
    """`loc: msg` per error, input values left out (they may be secrets)."""

    lines = []
    for error in e.errors():
        loc = ".".join(str(part) for part in (prefix, *error["loc"]) if part != "")
        lines.append(f"{loc}: {error['msg']}" if loc else error["msg"])
    return lines


def load_manifest(repo: Repo, overlay: dict[str, Any] | None) -> Manifest:
    """astrarium.yaml merged with allow-listed overlay (None: no overlay), validated."""

    raw = read_raw(repo.manifest)
    if overlay:
        validate_overlay(overlay)
        raw = merge_overlay(raw, overlay)
    try:
        return Manifest.model_validate(raw)
    except ValidationError as e:
        raise InvalidManifest(f"{repo.manifest.name}: " + "; ".join(validation_lines(e))) from None
