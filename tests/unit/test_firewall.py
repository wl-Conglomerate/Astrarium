"""SSH rules generated from control."""

import pytest
from nullforge.molds import FirewallRule

from astrarium.components.manifest.firewall import ssh_rules, ssh_sources
from astrarium.components.manifest.models import Manifest
from astrarium.errors import InvalidManifest


pytestmark = pytest.mark.unit


def manifest(ssh_allow: list, *, jump: str | None = "edge") -> Manifest:
    return Manifest.model_validate(
        {
            "deployment": {"name": "t", "domain": "example.net"},
            "control": {"jump": jump, "ssh_allow": ssh_allow},
            "nodes": {
                "nlA00": {
                    "role": "exit",
                    "ipv4": "203.0.113.10",
                    "ssh": {"port": 2222},
                },
                "edge": {
                    "role": "bastion",
                    "ipv4": "198.51.100.20",
                    "ipv6": "2001:db8::20",
                    "ssh": {"port": 22443},
                },
            },
        }
    )


def test_rule_text_keeps_source_and_comment_verbatim():
    model = manifest([{"source": "192.0.2.7", "comment": "Home SSH"}, "2001:db8:2:25d::"], jump=None)
    rules = ssh_rules(
        model,
        model.nodes["nlA00"],
        "exit",
    )
    assert [FirewallRule.model_validate(rule).model_dump() for rule in rules] == [
        FirewallRule(
            port=2222,
            proto="tcp",
            from_ip="192.0.2.7",
            comment="Home SSH",
        ).model_dump(),
        FirewallRule(
            port=2222,
            proto="tcp",
            from_ip="2001:db8:2:25d::",
        ).model_dump(),
    ]


def test_jump_addresses_are_added_once_whatever_the_spelling():
    model = manifest([{"source": "198.51.100.20/32", "comment": "Bastion SSH"}])
    sources = [allow.source for allow in ssh_sources(model)]
    assert sources == ["198.51.100.20/32", "2001:db8::20"]


@pytest.mark.parametrize(
    "source",
    [
        "198.51.100.7/24",
        "not-an-ip",
        "2001:db8::1/32",
        "",
    ],
)
def test_invalid_or_host_bit_sources_are_rejected(source):
    with pytest.raises(InvalidManifest):
        ssh_sources(manifest([source], jump=None))


def test_bastion_gets_no_generated_rules():
    model = manifest(["192.0.2.7"])
    assert (
        ssh_rules(
            model,
            model.nodes["edge"],
            "bastion",
        )
        == []
    )
