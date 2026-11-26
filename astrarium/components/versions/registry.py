"""Component registry: astrarium-owned xray, NullForge pins with verified apply paths, uv.lock tool stack."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from nullforge.molds.features import FEATURE_MOLD_MAPPING
from nullforge.smithy.versions import DEFAULT_VERSIONS, VERSION_COMMANDS, VERSION_MARKER_DIR

from astrarium.components.manifest.models import Manifest, VersionPin, XrayRelease
from astrarium.components.rollout.artifacts import XRAY_REPO
from astrarium.errors import InvalidManifest


Owner = Literal["astrarium", "nullforge", "tooling"]

MAIN_PIN = re.compile(r"^main@[0-9a-f]{40}$")

NULLFORGE_COMPONENTS: Mapping[str, tuple[str, str | None, str, str | None]] = {
    "blocky": (
        "0xERR0R/blocky",
        "/usr/bin/blocky",
        "dns",
        "dns:mode=blocky",
    ),
    "cloudflared": (
        "cloudflare/cloudflared",
        "/usr/bin/cloudflared",
        "zerotrust",
        "zerotrust",
    ),
    "curl": (
        "stunnel/static-curl",
        "/usr/local/bin/curl",
        "base",
        None,
    ),
    "direnv": (
        "direnv/direnv",
        "/usr/local/bin/direnv",
        "profiles",
        "profiles",
    ),
    "doggo": (
        "mr-karan/doggo",
        "/usr/local/bin/doggo",
        "base",
        None,
    ),
    "eza": (
        "eza-community/eza",
        "/usr/local/bin/eza",
        "profiles",
        "profiles",
    ),
    "nerd_fonts": (
        "ryanoasis/nerd-fonts",
        None,
        "profiles",
        "profiles",
    ),
    "nvim": (
        "neovim/neovim",
        "/usr/bin/nvim-source/AppRun",
        "profiles",
        "profiles",
    ),
    "telemt": (
        "telemt/telemt",
        "/usr/local/bin/telemt",
        "telemt",
        "telemt",
    ),
    "tmux": (
        "tmux/tmux",
        "/usr/local/bin/tmux",
        "profiles",
        "profiles",
    ),
    "usque": (
        "Diniboy1123/usque",
        "/usr/local/bin/usque",
        "warp",
        "warp:engine_type=masque",
    ),
    "wgcf": (
        "ViRb3/wgcf",
        "/usr/local/bin/wgcf",
        "warp",
        "warp:engine_type=wireguard",
    ),
}
"""Name -> (upstream repo, installed binary, rune applying it, feature gate), checked against NullForge sources."""

TAG_TEMPLATES: Mapping[str, str] = {
    "doggo": "v{version}",
    "usque": "v{version}",
    "wgcf": "v{version}",
}
"""Release tag per pin where it differs from pin itself, matching NullForge smithy tag forms."""

TOOL_STACK: Mapping[str, str] = {
    "astrarium": "wl-Conglomerate/Astrarium",
    "hexrift": "wlix13/HexRift",
    "nullforge": "wlix13/NullForge",
    "manticora": "wlix13/Manticora",
}
"""Tool stack packages read from uv.lock and their release repos (tags vX.Y.Z)."""

_LOCK_CACHE: dict[tuple[str, int, int], dict[str, str]] = {}
"""Parsed uv.lock per (path, mtime_ns, size), so one command reads and parses the lock once."""


def unmapped_nullforge_components() -> list[str]:
    return sorted(set(DEFAULT_VERSIONS) - set(NULLFORGE_COMPONENTS))


@dataclass(frozen=True)
class Component:
    name: str
    owner: Owner
    upstream: str | None
    binary: str | None
    probe: str | None
    rune: str | None
    feature: str | None


XRAY = Component(
    name="xray",
    owner="astrarium",
    upstream=XRAY_REPO,
    binary="/usr/local/bin/xray",
    probe="/usr/local/bin/xray version",
    rune=None,
    feature="xray",
)


def tag_for(component: Component, version: str) -> str:
    """Upstream release tag of pinned version."""

    if component.owner == "tooling":
        return f"v{version}"
    return TAG_TEMPLATES.get(component.name, "{version}").format(version=version)


def version_from_tag(component: Component, tag: str) -> str:
    """Pin form of upstream release tag (inverse of tag_for)."""

    if component.owner == "tooling" or component.name in TAG_TEMPLATES:
        return tag.removeprefix("v")
    return tag


def version_key(version: str) -> tuple[int, ...]:
    """Numeric parts of leading dotted version run, for ordering pins against upstream tags.
    Suffix-only differences (trailing `-rc1`, `b`, `+build`, ...) compare equal."""

    match = re.match(r"v?(\d+(?:\.\d+)*)", version)
    if match is None:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def feature_enabled(features: Mapping[str, Any], gate: str | None) -> bool:
    """Gate `attr` (NullForge mold is_active) or `attr:field=value` over validated features dump, None always on."""

    if gate is None:
        return True
    attr, _, condition = gate.partition(":")
    mold = FEATURE_MOLD_MAPPING.get(attr)
    if mold is None:
        raise InvalidManifest(f"unknown feature gate {gate!r}")
    section = features.get(attr, {})
    if not mold.model_validate(section).is_active:
        return False
    if not condition:
        return True
    field, _, value = condition.partition("=")
    return str(section.get(field, "")) == value


def validate_gate(gate: str | None) -> None:
    """InvalidManifest unless gate names NullForge feature and, with condition, one of its fields."""

    if gate is None:
        return
    attr, _, condition = gate.partition(":")
    mold = FEATURE_MOLD_MAPPING.get(attr)
    if mold is None:
        raise InvalidManifest(
            f"feature gate {gate!r} names no NullForge feature",
            hint=f"features: {', '.join(sorted(FEATURE_MOLD_MAPPING))}",
        )
    if condition:
        field, separator, _ = condition.partition("=")
        if not separator or field not in mold.model_fields:
            raise InvalidManifest(f"feature gate {gate!r} needs field=value with a field of {attr}")


def lock_versions(text: str) -> dict[str, str]:
    """Tool stack versions from uv.lock text."""

    data = tomllib.loads(text)
    return {
        package["name"]: package["version"]
        for package in data.get("package", [])
        if package.get("name") in TOOL_STACK and "version" in package
    }


def tool_stack_versions(lockfile: Path) -> dict[str, str]:
    """Tool stack versions pinned in uv.lock, empty without lockfile. Parsed once per file state."""

    if not lockfile.is_file():
        return {}
    stat = lockfile.stat()
    key = (
        str(lockfile),
        stat.st_mtime_ns,
        stat.st_size,
    )
    if key not in _LOCK_CACHE:
        _LOCK_CACHE[key] = lock_versions(lockfile.read_text(encoding="utf-8"))
    return _LOCK_CACHE[key]


def _nullforge_component(name: str) -> Component:
    mapped = NULLFORGE_COMPONENTS.get(name)
    if mapped is None:
        return Component(
            name=name,
            owner="nullforge",
            upstream=None,
            binary=None,
            probe=None,
            rune=None,
            feature=None,
        )
    upstream, binary, rune, gate = mapped
    probe: str | None = None
    if name in VERSION_COMMANDS:
        command = VERSION_COMMANDS[name]
        probe = f"cat {VERSION_MARKER_DIR}/{name}" if command is None else command.format(bin=binary)
    return Component(
        name=name,
        owner="nullforge",
        upstream=upstream,
        binary=binary,
        probe=probe,
        rune=rune,
        feature=gate,
    )


def build_registry(manifest: Manifest, lockfile: Path) -> dict[str, Component]:
    """Registry: xray, every NullForge default, manifest `components:` under new names, tool stack found in uv.lock."""

    registry: dict[str, Component] = {"xray": XRAY}
    for name in sorted(DEFAULT_VERSIONS):
        registry[name] = _nullforge_component(name)
    builtin = {
        XRAY.name,
        *DEFAULT_VERSIONS,
        *NULLFORGE_COMPONENTS,
        *TOOL_STACK,
    }
    for name, spec in sorted(manifest.components.items()):
        if name in builtin:
            raise InvalidManifest(
                f"components.{name} reuses a built-in component name", hint="give custom components new names"
            )
        validate_gate(spec.feature)
        try:
            probe = spec.probe.format(bin=spec.binary) if spec.probe is not None else None
        except (
            KeyError,
            IndexError,
            ValueError,
        ) as e:
            raise InvalidManifest(
                f"components.{name}.probe is not a valid template", hint="only {bin} is substituted"
            ) from e
        registry[name] = Component(
            name=name,
            owner="nullforge",
            upstream=spec.upstream,
            binary=spec.binary,
            probe=probe,
            rune=spec.rune,
            feature=spec.feature,
        )
    for name in sorted(tool_stack_versions(lockfile)):
        registry[name] = Component(
            name=name,
            owner="tooling",
            upstream=TOOL_STACK[name],
            binary=None,
            probe=None,
            rune=None,
            feature=None,
        )
    return registry


def pin_layer(manifest: Manifest, name: str, node_id: str | None = None) -> tuple[VersionPin | None, str]:
    """Effective pin and layer that set it: node override, manifest, NullForge default."""

    if node_id is not None:
        node_pins = manifest.nodes[node_id].overrides.versions
        if name in node_pins:
            return node_pins[name], f"node {node_id}"
    if name in manifest.versions:
        return manifest.versions[name], "manifest"
    if name in DEFAULT_VERSIONS:
        return DEFAULT_VERSIONS[name], "nullforge default"
    return None, "unpinned"


def _pins(manifest: Manifest) -> list[tuple[str, str, VersionPin]]:
    found = [
        (
            "versions",
            name,
            pin,
        )
        for name, pin in manifest.versions.items()
    ]
    for node_id, spec in manifest.nodes.items():
        found += [
            (
                f"nodes.{node_id}.overrides.versions",
                name,
                pin,
            )
            for name, pin in spec.overrides.versions.items()
        ]
    return found


def check_pins(manifest: Manifest, registry: Mapping[str, Component]) -> None:
    """InvalidManifest for pins NullForge would ignore or misread: unknown names, tool stack, wrong shapes."""

    problems: list[str] = []
    for where, name, pin in _pins(manifest):
        component = registry.get(name)
        if component is None:
            problems.append(f"{where}.{name}: unknown component")
        elif component.owner == "tooling":
            problems.append(f"{where}.{name}: tool stack versions live in uv.lock (arium versions bump {name} VER)")
        elif component.owner == "astrarium":
            if not isinstance(pin, XrayRelease) and not (isinstance(pin, str) and MAIN_PIN.fullmatch(pin)):
                problems.append(f"{where}.{name}: use {{version, sha256}} or main@<40-hex sha>")
        elif not isinstance(pin, str):
            problems.append(f"{where}.{name}: NullForge pins are plain version strings")
    if problems:
        raise InvalidManifest("invalid version pins: " + "; ".join(problems), hint="see `arium versions list --all`")


def listed_components(registry: Mapping[str, Component], manifest: Manifest, *, all_components: bool) -> list[str]:
    """Components shown by `versions list` and `status`: pinned ones, xray, tool stack, every default with all."""

    names = {"xray", *(name for name, item in registry.items() if item.owner == "tooling")}
    names |= {name for _, name, _ in _pins(manifest)}
    if all_components:
        names |= {name for name, item in registry.items() if item.owner == "nullforge"}
    order = {
        "astrarium": 0,
        "nullforge": 1,
        "tooling": 2,
    }
    return sorted((name for name in names if name in registry), key=lambda name: (order[registry[name].owner], name))


def apply_label(component: Component) -> str:
    """How pin of component reaches nodes."""

    if component.owner == "astrarium":
        return "arium fleet deploy"
    if component.owner == "tooling":
        return "arium versions bump (uv add)"
    if component.rune is None:
        return "no apply path"
    return f"-r {component.rune}"
