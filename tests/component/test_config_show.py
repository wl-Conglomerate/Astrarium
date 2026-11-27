"""`arium config show` / `config schema`."""

import json
from pathlib import Path

import pytest

from astrarium import __main__ as entry
from astrarium.components.secrets.masking import MASK
from tests.support.deployment import TELEMT_SECRET, fixture_app, make_deployment


pytestmark = pytest.mark.component


def test_show_masks_secrets_and_names_layers(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    view = fixture_app(root).manifest.show(["mskP00"])["mskP00"]
    values = {row["path"]: row for row in view["values"]}
    assert values["features.telemt.users"]["value"] == MASK
    assert values["features.telemt.tls_domain"] == {
        "path": "features.telemt.tls_domain",
        "value": "www.example.org",
        "layer": "role:pulsar",
    }
    assert values["features.telemt.port"]["layer"] == "preset:pulsar"
    assert values["system.hostname"]["value"] == "mskP00.pulsar"
    assert TELEMT_SECRET not in json.dumps(view)


def test_show_without_defaults_hides_values_no_layer_sets(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    app = fixture_app(root)
    short = {row["path"] for row in app.manifest.show(["nlA00"])["nlA00"]["values"]}
    full = {row["path"] for row in app.manifest.show(["nlA00"], defaults=True)["nlA00"]["values"]}
    assert "features.tor.install" not in short
    assert "features.tor.install" in full


def test_show_names_the_manifest_layer_for_an_xray_release_pin(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    manifest_path = root / "astrarium.yaml"
    sha = "a" * 64
    manifest_path.write_text(
        manifest_path.read_text().replace(
            "versions:\n  telemt: 3.5.7\n",
            f"versions:\n  telemt: 3.5.7\n  xray: {{version: v26.3.27, sha256: {{x86_64: {sha}}}}}\n",
        )
    )
    values = {row["path"]: row for row in fixture_app(root).manifest.show(["nlA00"])["nlA00"]["values"]}
    assert values["versions.xray.version"] == {
        "path": "versions.xray.version",
        "value": "v26.3.27",
        "layer": "manifest",
    }
    assert values["versions.xray.sha256.x86_64"] == {
        "path": "versions.xray.sha256.x86_64",
        "value": sha,
        "layer": "manifest",
    }


def test_schema_command_needs_no_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as caught:
        entry.main(["config", "schema"])
    assert caught.value.code == 0
    assert "nodes" in json.loads(capsys.readouterr().out)["properties"]
