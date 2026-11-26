"""Round-trip manifest edits keep comments and layout."""

from pathlib import Path

import pytest
import yaml

from astrarium.components.manifest.edit import ManifestEditor
from astrarium.components.manifest.models import XrayRelease
from astrarium.errors import InvalidManifest


pytestmark = pytest.mark.component

INDENTED = """\
# Deployment manifest (hand written)
deployment:
  name: test   # used in run ids
  domain: example.net

control:
  ssh_allow:
    - {source: 192.0.2.7, comment: Home SSH}

versions:
  telemt: '3.5.7'   # pinned by hand

nodes:
  nlA00:
    role: exit
    ipv4: 203.0.113.10
"""

FLUSH = """\
deployment:
  name: test
control:
  ssh_allow:
  - source: 192.0.2.7
    comment: Home SSH
nodes:
  nlA00:
    role: exit
    ipv4: 203.0.113.10
"""

FLUSH_COMMENTED = FLUSH.replace("  ssh_allow:\n", "  ssh_allow:\n  # home connection\n")

HEADED = "# fleet manifest\n--- # document start\n" + FLUSH

RELEASE = XrayRelease(version="v26.3.27", sha256={"x86_64": "a" * 64, "aarch64": "b" * 64})


@pytest.mark.parametrize(
    "text",
    [
        INDENTED,
        FLUSH,
        FLUSH_COMMENTED,
        HEADED,
    ],
)
def test_edits_keep_every_untouched_line(tmp_path: Path, text: str):
    path = tmp_path / "astrarium.yaml"
    path.write_text(text)
    editor = ManifestEditor(path)
    editor.set_version("xray", RELEASE)
    editor.set_version(
        "telemt",
        "3.5.8",
        node="nlA00",
    )
    editor.save()
    result = path.read_text()
    assert all(line in result.splitlines() for line in text.splitlines())
    data = yaml.safe_load(result)
    assert data["versions"]["xray"] == {"version": "v26.3.27", "sha256": {"aarch64": "b" * 64, "x86_64": "a" * 64}}
    assert data["nodes"]["nlA00"]["overrides"]["versions"]["telemt"] == "3.5.8"


def test_document_start_and_lines_before_it_are_kept(tmp_path: Path):
    path = tmp_path / "astrarium.yaml"
    path.write_text(HEADED)
    editor = ManifestEditor(path)
    editor.set_version("telemt", "3.5.8")
    editor.save()
    assert path.read_text().startswith("# fleet manifest\n--- # document start\ndeployment:\n")


@pytest.mark.parametrize(
    "text",
    [
        None,
        "",
        "- a list\n",
        "key: [unclosed\n",
        "---\n",
    ],
)
def test_unreadable_or_non_mapping_manifest_is_invalid(tmp_path: Path, text: str | None):
    path = tmp_path / "astrarium.yaml"
    if text is not None:
        path.write_text(text)
    with pytest.raises(InvalidManifest):
        ManifestEditor(path)


def test_edit_that_breaks_manifest_is_not_written(tmp_path: Path):
    path = tmp_path / "astrarium.yaml"
    path.write_text(FLUSH)
    editor = ManifestEditor(path)
    editor.set_version("xray", "v26.3.27")
    with pytest.raises(InvalidManifest):
        editor.save()
    assert path.read_text() == FLUSH


def test_unknown_node_is_refused(tmp_path: Path):
    path = tmp_path / "astrarium.yaml"
    path.write_text(FLUSH)
    with pytest.raises(InvalidManifest):
        ManifestEditor(path).set_version(
            "telemt",
            "3.5.8",
            node="deA00",
        )
