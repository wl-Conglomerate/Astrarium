"""`arium keys gen` / `keys show`."""

from pathlib import Path

import pytest

from astrarium.errors import UsageProblem
from tests.support.deployment import fixture_app, make_deployment


pytestmark = pytest.mark.component

HOST_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIAYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG"


def test_gen_creates_missing_key_files_only(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    app = fixture_app(root)
    assert set(app.keys.gen([])) == {"mskA00", "nlA00"}
    before = (root / "secrets" / "keys" / "nlA00.yaml").read_bytes()
    assert app.keys.gen([]) == []
    assert (root / "secrets" / "keys" / "nlA00.yaml").read_bytes() == before
    assert set(app.keys.show("nlA00")) == {
        "reality_private_key",
        "reality_public_key",
        "decryption",
        "encryption",
    }


def test_new_hub_copies_keys_of_same_config_sibling(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    topology = root / "topology.yaml"
    topology.write_text(topology.read_text() + "      - id: mskA01\n        hostname: mskA01.perigee.example.net\n")
    manifest = root / "astrarium.yaml"
    new_node = f"  mskA01:\n    role: hub\n    ipv4: 203.0.113.21\n    host_keys: {{ed25519: {HOST_KEY}}}\n"
    manifest.write_text(manifest.read_text().replace("  mskP00:\n", new_node + "  mskP00:\n"))
    app = fixture_app(root)
    assert set(app.keys.gen(["mskA01"])) == {"mskA01"}
    assert app.keys.show("mskA01") == app.keys.show("mskA00")


def test_gen_refuses_nodes_outside_topology(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    with pytest.raises(UsageProblem):
        fixture_app(root).keys.gen(["mskP00"])
