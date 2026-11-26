"""Registry against pinned NullForge sources and uv.lock."""

import importlib.util
import inspect
from pathlib import Path

import pytest
from nullforge.runes import rune_path
from nullforge.smithy.versions import DEFAULT_VERSIONS, Versions

from astrarium.components.versions.registry import (
    NULLFORGE_COMPONENTS,
    TAG_TEMPLATES,
    build_registry,
    tool_stack_versions,
    validate_gate,
)
from tests.support.fleet import fleet, manifest_from


pytestmark = pytest.mark.component

INSTALLERS = (
    "nullforge.runes.base",
    "nullforge.runes.profiles",
    "nullforge.runes.telemt",
    "nullforge.smithy.blocky",
    "nullforge.smithy.cloudflare",
    "nullforge.models.warp",
)

URL_BUILDERS = {
    "blocky": Versions.blocky_tar,
    "cloudflared": Versions.cloudflared_url,
    "curl": Versions.curl_tar,
    "direnv": Versions.direnv_url,
    "doggo": Versions.doggo_tar,
    "eza": Versions.eza_tar,
    "nerd_fonts": Versions.nerd_font_tar,
    "nvim": Versions.nvim_appimage,
    "telemt": Versions.telemt_tar,
    "tmux": Versions.tmux_tar,
    "usque": Versions.usque_zip,
    "wgcf": Versions.wgcf_url,
}


def _source(module):
    spec = importlib.util.find_spec(module)
    assert spec is not None
    assert spec.origin is not None
    return Path(spec.origin).read_text(encoding="utf-8")


def test_nullforge_components_cover_every_default_version():
    """New DEFAULT_VERSIONS entry without mapping fails CI instead of silently losing upstream/probe."""

    assert set(NULLFORGE_COMPONENTS) == set(DEFAULT_VERSIONS)


def test_component_table_matches_pinned_nullforge_sources():
    installers = "".join(_source(module) for module in INSTALLERS)
    for name, (
        upstream,
        binary,
        rune,
        gate,
    ) in NULLFORGE_COMPONENTS.items():
        assert name in DEFAULT_VERSIONS, name
        assert rune_path(rune).is_file(), rune
        validate_gate(gate)
        builder = inspect.getsource(URL_BUILDERS[name])
        assert f'"{upstream}"' in builder, (name, upstream)
        assert ('f"v{version}"' in builder) is (name in TAG_TEMPLATES), name
        if binary is not None:
            assert f'"{binary}"' in installers, (name, binary)


def test_tool_stack_comes_from_uv_lock(tmp_path):
    lock = tmp_path / "uv.lock"
    lock.write_text(
        'version = 1\n\n[[package]]\nname = "hexrift"\nversion = "0.13.0"\n'
        'source = { registry = "https://photon.example.net/simple/" }\n\n'
        '[[package]]\nname = "rich"\nversion = "14.0.0"\nsource = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    registry = build_registry(manifest_from(fleet()), lock)
    assert registry["hexrift"].owner == "tooling"
    assert "rich" not in registry
    assert tool_stack_versions(lock) == {"hexrift": "0.13.0"}
