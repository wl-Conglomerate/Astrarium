"""Manifest loading from files."""

from pathlib import Path

import pytest

from astrarium.components.manifest.loader import load_manifest, read_raw
from astrarium.errors import InvalidManifest
from astrarium.repo import Repo


pytestmark = pytest.mark.component

SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"

MANIFEST = """\
deployment: {name: test, domain: example.net}
roles:
  pulsar:
    features:
      telemt: {tls_domain: www.example.org}
nodes:
  mskP00: {role: pulsar, ipv4: 203.0.113.30}
"""


def test_load_manifest_merges_allowed_overlay(tmp_path: Path):
    (tmp_path / "astrarium.yaml").write_text(MANIFEST)
    overlay = {
        "topology": {"namespace": "ns"},
        "roles": {"pulsar": {"features": {"telemt": {"users": {"alice": SECRET}}}}},
    }
    manifest = load_manifest(Repo(tmp_path), overlay)
    assert manifest.roles["pulsar"].features["telemt"] == {"tls_domain": "www.example.org", "users": {"alice": SECRET}}


def test_load_manifest_refuses_overlay_outside_allow_list(tmp_path: Path):
    (tmp_path / "astrarium.yaml").write_text(MANIFEST)
    with pytest.raises(InvalidManifest):
        load_manifest(Repo(tmp_path), {"control": {"deploy_keys": ["ssh-ed25519 AAAA x"]}})


def test_invalid_manifest_reports_path_without_value(tmp_path: Path):
    (tmp_path / "astrarium.yaml").write_text(MANIFEST.replace("203.0.113.30", "not-an-address-secretish"))
    with pytest.raises(InvalidManifest) as caught:
        load_manifest(Repo(tmp_path), None)
    assert "nodes.mskP00.ipv4" in caught.value.message
    assert "not-an-address-secretish" not in caught.value.message


@pytest.mark.parametrize("text", ["- a list\n", "key: [unclosed\n"])
def test_read_raw_rejects_non_mapping_and_broken_yaml(tmp_path: Path, text: str):
    path = tmp_path / "astrarium.yaml"
    path.write_text(text)
    with pytest.raises(InvalidManifest):
        read_raw(path)


def test_read_raw_of_empty_file_is_empty_mapping(tmp_path: Path):
    path = tmp_path / "astrarium.yaml"
    path.write_text("")
    assert read_raw(path) == {}


def test_read_raw_of_missing_file_is_invalid_manifest(tmp_path: Path):
    with pytest.raises(InvalidManifest):
        read_raw(tmp_path / "astrarium.yaml")
