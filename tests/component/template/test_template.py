"""Copier template renders loadable deployment skeleton."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest
import yaml

from astrarium.components.check.throwaway import random_namespace
from astrarium.components.manifest.models import Manifest
from astrarium.components.topology.bridge import (
    NAMESPACE_PLACEHOLDER,
    hexrift_nodes,
    materialize_topology,
    open_hexrift,
)
from astrarium.components.versions.registry import TOOL_STACK
from tests.support.template import AGE_RECIPIENT, SSH_RECIPIENT, render


pytestmark = pytest.mark.component


def test_skeleton_loads_with_astrarium_and_hexrift(tmp_path: Path) -> None:
    out = render(tmp_path, jump="edge")

    manifest = Manifest.model_validate(yaml.safe_load((out / "astrarium.yaml").read_text()))
    topology = yaml.safe_load((out / "topology.yaml").read_text())
    app = open_hexrift(
        materialize_topology(
            out / "topology.yaml",
            tmp_path / "materialized.yaml",
            random_namespace(),
        )
    )

    assert manifest.deployment.name == "test"
    assert manifest.control.jump == "edge"
    assert topology["global"]["namespace"] == NAMESPACE_PLACEHOLDER
    assert topology["global"]["aphelion_domain"] == f"{manifest.deployment.names['exit']}.{manifest.deployment.domain}"
    assert hexrift_nodes(app) == {}
    assert ".astrarium/" in (out / ".gitignore").read_text().splitlines()
    assert not (out / "secrets" / "astrarium.sops.yaml").exists()


def test_pyproject_pins_tool_stack_from_photon_only(tmp_path: Path) -> None:
    plain = tomllib.loads((render(tmp_path / "plain") / "pyproject.toml").read_text())
    dns = tomllib.loads((render(tmp_path / "dns", has_dns=True) / "pyproject.toml").read_text())

    assert set(plain["project"]["dependencies"]) == {
        "astrarium==0.1.0",
        "hexrift==0.13.0",
        "nullforge==0.4.0",
    }
    assert "manticora==1.0.0" in dns["project"]["dependencies"]
    assert plain["tool"]["uv"]["package"] is False
    assert plain["tool"]["uv"]["index"] == [
        {
            "name": "photon",
            "url": "https://photon.example.net/simple/",
            "explicit": True,
        }
    ]
    assert plain["tool"]["uv"]["sources"] == {name: {"index": "photon"} for name in TOOL_STACK}


def test_sops_rule_covers_every_secret_file_and_lists_recipients(tmp_path: Path) -> None:
    quoted = f"""{SSH_RECIPIENT} "work" 'laptop' C:\\keys"""
    out = render(tmp_path, age_recipients=f"{AGE_RECIPIENT}\n{quoted}")
    rules = yaml.safe_load((out / ".sops.yaml").read_text())["creation_rules"]

    pattern = re.compile(rules[0]["path_regex"])
    assert len(rules) == 1
    assert pattern.search("secrets/keys/nlA00.yaml")
    assert pattern.search("/home/op/deployment/secrets/astrarium.sops.yaml")
    assert not pattern.search("topology.yaml")
    assert set(rules[0]["age"].split(",")) == {AGE_RECIPIENT, quoted}


@pytest.mark.parametrize(
    "bad",
    [
        "age1short",
        f"{SSH_RECIPIENT} work,laptop",
        "ssh-ed25519 not-base64!",
    ],
)
def test_invalid_recipient_is_rejected_without_echo(tmp_path: Path, bad: str) -> None:
    with pytest.raises(ValueError) as caught:
        render(tmp_path, age_recipients=f"{AGE_RECIPIENT}\n{bad}")

    assert bad not in str(caught.value)


def test_dns_answer_adds_config_without_zone_files(tmp_path: Path) -> None:
    assert not (render(tmp_path / "plain") / "dns").exists()
    out = render(tmp_path / "dns", has_dns=True)

    config = yaml.safe_load((out / "dns" / "config.yaml").read_text())

    assert list(config["zones"]) == ["example.net."]
    assert config["providers"]["cloudflare"]["token"] == "env/CLOUDFLARE_API_TOKEN"
    assert [path.name for path in (out / "dns").iterdir()] == ["config.yaml"]


def test_invalid_deployment_name_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        render(tmp_path, deployment_name="Main Fleet")
