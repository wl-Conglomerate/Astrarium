"""HexRift bridge on fixture topology."""

import json
from pathlib import Path

import pytest

from astrarium.components.topology.bridge import (
    NAMESPACE_PLACEHOLDER,
    build_nodes,
    gen_keys,
    haproxy_wanted,
    hexrift_nodes,
    materialize_topology,
    open_hexrift,
    topology_namespace,
)
from astrarium.errors import ExternalToolError, InvalidManifest
from tests.support.deployment import FIXTURE, NAMESPACE


pytestmark = pytest.mark.component


def materialized(tmp_path: Path) -> Path:
    return materialize_topology(
        FIXTURE / "topology.yaml",
        tmp_path / "topology.yaml",
        NAMESPACE,
    )


def test_materialize_injects_namespace_and_keeps_other_bytes(tmp_path: Path):
    target = materialized(tmp_path)
    source = (FIXTURE / "topology.yaml").read_text()
    assert target.read_text() == source.replace(NAMESPACE_PLACEHOLDER, NAMESPACE)
    assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("quote", ["'", '"'])
def test_materialize_keeps_quote_character(tmp_path: Path, quote: str):
    src = tmp_path / "src.yaml"
    text = (FIXTURE / "topology.yaml").read_text().replace(NAMESPACE_PLACEHOLDER, quote + NAMESPACE_PLACEHOLDER + quote)
    src.write_text(text)
    target = materialize_topology(
        src,
        tmp_path / "out.yaml",
        NAMESPACE,
    )
    assert target.read_text() == text.replace(NAMESPACE_PLACEHOLDER, NAMESPACE)


def test_materialize_refuses_topology_holding_a_real_namespace(tmp_path: Path):
    src = tmp_path / "src.yaml"
    src.write_text((FIXTURE / "topology.yaml").read_text().replace(NAMESPACE_PLACEHOLDER, "leaked-real-namespace"))
    with pytest.raises(InvalidManifest):
        materialize_topology(
            src,
            tmp_path / "out.yaml",
            NAMESPACE,
        )


@pytest.mark.parametrize("text", ["global:\n", "global: not-a-mapping\n"])
def test_empty_or_scalar_global_section_reads_as_absent(tmp_path: Path, text: str):
    src = tmp_path / "topology.yaml"
    src.write_text(text + "nodes: []\n")
    assert topology_namespace(src) is None


def test_materialize_refuses_empty_global_section_as_missing_placeholder(tmp_path: Path):
    src = tmp_path / "src.yaml"
    src.write_text("global:\nnodes: []\n")
    with pytest.raises(InvalidManifest):
        materialize_topology(
            src,
            tmp_path / "out.yaml",
            NAMESPACE,
        )


def test_open_hexrift_wraps_schema_errors_without_markup(tmp_path: Path):
    broken = tmp_path / "topology.yaml"
    broken.write_text(materialized(tmp_path).read_text().replace("vless_route: 1000", "vless_route: -1"))
    with pytest.raises(ExternalToolError) as caught:
        open_hexrift(broken)
    assert "[red]" not in caught.value.message


def test_nodes_keys_and_builds(tmp_path: Path):
    app = open_hexrift(materialized(tmp_path))
    nodes = hexrift_nodes(app)
    assert {
        (
            n.id,
            n.region,
            n.type,
            n.hostname,
        )
        for n in nodes.values()
    } == {
        (
            "nlA00",
            "nl",
            "exit",
            "nlA00.aphelion.example.net",
        ),
        (
            "mskA00",
            "msk",
            "hub",
            "mskA00.perigee.example.net",
        ),
    }
    keys = tmp_path / "keys"
    assert sorted(
        gen_keys(
            app,
            sorted(nodes),
            keys,
        )
    ) == ["mskA00", "nlA00"]
    before = (keys / "mskA00.yaml").read_bytes()
    assert (
        gen_keys(
            app,
            ["mskA00"],
            keys,
        )
        == []
    )
    assert (keys / "mskA00.yaml").read_bytes() == before
    built = build_nodes(
        app,
        ["mskA00"],
        keys,
        tmp_path / "out",
    )
    assert json.loads(built["mskA00"].config_json.read_text())["inbounds"]
    assert built["mskA00"].haproxy_wanted is True


def test_hub_build_without_exit_keys_fails(tmp_path: Path):
    app = open_hexrift(materialized(tmp_path))
    keys = tmp_path / "keys"
    gen_keys(
        app,
        ["mskA00"],
        keys,
    )
    with pytest.raises(ExternalToolError):
        build_nodes(
            app,
            ["mskA00"],
            keys,
            tmp_path / "out",
        )


@pytest.mark.parametrize(
    ("text", "wanted"),
    [
        ("global\n  daemon\n", False),
        ("defaults\n  mode tcp\nfrontend fe_edge\n  bind :443\n", True),
        ("  LISTEN stats\n", True),
        ("# frontend commented out\nbackend bk\n", False),
    ],
)
def test_haproxy_wanted_follows_frontend_or_listen_sections(text, wanted):
    assert haproxy_wanted(text) is wanted
