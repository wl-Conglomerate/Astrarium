"""Render Copier template of this checkout without git or tasks."""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from copier import run_copy


TOOL_ROOT = Path(__file__).resolve().parents[2]

AGE_RECIPIENT = "age1" + "q" * 58

SSH_RECIPIENT = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITemplateTestKeyOnly00000000000000000000 operator"

DEFAULT_ANSWERS: dict[str, Any] = {
    "deployment_name": "test",
    "domain": "example.net",
    "jump": "",
    "photon_url": "https://photon.example.net/simple/",
    "age_recipients": f"{AGE_RECIPIENT}\n{SSH_RECIPIENT}",
    "has_dns": False,
    "manticora_version": "1.0.0",
    "astrarium_version": "0.1.0",
    "hexrift_version": "0.13.0",
    "nullforge_version": "0.4.0",
}


def template_copy(dest: Path) -> Path:
    """copier.yml and template/ copied outside git, so Copier renders working tree as-is."""

    dest.mkdir(parents=True, exist_ok=True)
    source = TOOL_ROOT / "astrarium" / "_template"
    shutil.copy2(source / "copier.yml", dest / "copier.yml")
    shutil.copytree(source / "template", dest / "template")
    return dest


def render(tmp: Path, **answers: Any) -> Path:
    """Rendered deployment repo at `tmp`/out."""

    source = template_copy(tmp / "src")
    out = tmp / "out"
    run_copy(
        str(source),
        out,
        data={**DEFAULT_ANSWERS, **answers},
        defaults=True,
        quiet=True,
        unsafe=True,
        skip_tasks=True,
    )
    return out
