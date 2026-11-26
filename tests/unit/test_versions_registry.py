"""Component registry: NullForge pins with apply paths, gates, pin validation, listing."""

import pytest
from nullforge.smithy.versions import DEFAULT_VERSIONS

from astrarium.components.versions import registry as registry_module
from astrarium.components.versions.registry import (
    build_registry,
    check_pins,
    feature_enabled,
    listed_components,
    version_key,
)
from astrarium.errors import InvalidManifest
from tests.support.fleet import NO_LOCK, features, fleet, manifest_from


pytestmark = pytest.mark.unit

CUSTOM = {
    "owner": "nullforge",
    "upstream": "example/tool",
    "binary": "/usr/local/bin/tool",
    "probe": "{bin} --version",
    "rune": "tool",
    "feature": "containers",
}


def test_nullforge_components_follow_default_versions_with_verified_apply_paths():
    registry = build_registry(manifest_from(fleet()), NO_LOCK)
    assert set(DEFAULT_VERSIONS) <= set(registry)
    assert (registry["telemt"].rune, registry["telemt"].feature) == ("telemt", "telemt")
    assert (
        registry["blocky"].rune,
        registry["usque"].rune,
        registry["wgcf"].rune,
    ) == (
        "dns",
        "warp",
        "warp",
    )
    assert registry["wgcf"].probe == "cat /var/lib/nullforge/versions/wgcf"
    assert (registry["xray"].owner, registry["xray"].rune) == ("astrarium", None)


def test_unmapped_nullforge_default_has_no_apply_path(monkeypatch):
    monkeypatch.setattr(
        registry_module,
        "DEFAULT_VERSIONS",
        {**DEFAULT_VERSIONS, "newtool": "1.0.0"},
    )
    newtool = build_registry(manifest_from(fleet()), NO_LOCK)["newtool"]
    assert (
        newtool.owner,
        newtool.rune,
        newtool.probe,
    ) == (
        "nullforge",
        None,
        None,
    )


@pytest.mark.parametrize(
    (
        "sections",
        "gate",
        "enabled",
    ),
    [
        (
            {"warp": {"install": True, "engine_type": "masque"}},
            "warp:engine_type=masque",
            True,
        ),
        (
            {"warp": {"install": True, "engine_type": "wireguard"}},
            "warp:engine_type=masque",
            False,
        ),
        (
            {"warp": {"install": False}},
            "warp:engine_type=masque",
            False,
        ),
        (
            {"dns": {"mode": "dot_resolved"}},
            "dns:mode=blocky",
            False,
        ),
        (
            {"profiles": {"for_root": False}},
            "profiles",
            False,
        ),
        (
            {"telemt": {"install": False}},
            None,
            True,
        ),
    ],
)
def test_feature_gates_follow_nullforge_activity(sections, gate, enabled):
    assert feature_enabled(features(**sections), gate) is enabled


def test_check_pins_rejects_unknown_component():
    manifest = manifest_from(fleet(), versions={"telemtt": "3.5.7"})
    registry = build_registry(manifest, NO_LOCK)
    with pytest.raises(InvalidManifest):
        check_pins(manifest, registry)


def test_check_pins_rejects_tool_stack_pin(monkeypatch):
    monkeypatch.setattr(
        registry_module,
        "tool_stack_versions",
        lambda lockfile: {"hexrift": "0.13.0"},
    )
    manifest = manifest_from(fleet(), versions={"hexrift": "0.13.1"})
    registry = build_registry(manifest, NO_LOCK)
    with pytest.raises(InvalidManifest):
        check_pins(manifest, registry)


@pytest.mark.parametrize(
    ("version", "key"),
    [
        (
            "1.2.3",
            (
                1,
                2,
                3,
            ),
        ),
        (
            "1.2.3-rc1",
            (
                1,
                2,
                3,
            ),
        ),
        (
            "v1.2.3",
            (
                1,
                2,
                3,
            ),
        ),
        ("3.7b", (3, 7)),
    ],
)
def test_version_key_keeps_suffix_only_differences_equal(version, key):
    assert version_key(version) == key


def test_custom_component_extends_registry():
    registry = build_registry(manifest_from(fleet(), components={"tool": CUSTOM}), NO_LOCK)
    assert registry["tool"].probe == "/usr/local/bin/tool --version"


@pytest.mark.parametrize(
    "name",
    [
        "xray",
        "telemt",
        "hexrift",
    ],
)
def test_custom_component_cannot_reuse_a_builtin_name(name):
    with pytest.raises(InvalidManifest):
        build_registry(manifest_from(fleet(), components={name: CUSTOM}), NO_LOCK)


def test_default_listing_is_pinned_components_plus_xray_and_all_adds_every_default():
    manifest = manifest_from(
        fleet(),
        versions={"telemt": "3.5.7"},
        node_versions={"mskA10": {"usque": "4.2.0"}},
    )
    registry = build_registry(manifest, NO_LOCK)
    assert set(
        listed_components(
            registry,
            manifest,
            all_components=False,
        )
    ) == {
        "xray",
        "telemt",
        "usque",
    }
    assert set(DEFAULT_VERSIONS) <= set(
        listed_components(
            registry,
            manifest,
            all_components=True,
        )
    )
