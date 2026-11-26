"""Login users, routes and rendered SSH files."""

import base64
import struct
from pathlib import Path

import pytest

from astrarium.components.manifest.models import CiControl, ControlSection
from astrarium.components.sshcfg.render import hop_user, login_user, render_known_hosts, render_ssh_config, resolve_via
from astrarium.errors import InvalidManifest, UsageProblem
from tests.support.hostkeys import ed25519_blob
from tests.support.nodes import make_node


pytestmark = pytest.mark.unit

CONTROL = ControlSection(
    deploy_user="github_actions",
    jump="edge",
    ci=CiControl(cast_user="astrarium_ci"),
)


def _header_only_blob(key_type: str) -> str:
    return base64.b64encode(struct.pack(">I", len(key_type)) + key_type.encode()).decode()


def test_identities_pick_login_users() -> None:
    node = make_node(
        "nlA00",
        ssh_user=None,
        admin_user="operator",
    )
    pinned = make_node(
        "edge",
        role="bastion",
        ssh_user="root",
        admin_user=None,
    )

    assert (
        login_user(
            node,
            "deploy",
            CONTROL,
        )
        == "github_actions"
    )
    assert (
        login_user(
            node,
            "ci",
            CONTROL,
        )
        == "astrarium_ci"
    )
    assert (
        login_user(
            node,
            "admin",
            CONTROL,
        )
        == "operator"
    )
    assert (
        login_user(
            pinned,
            "admin",
            CONTROL,
        )
        == "root"
    )


def test_hop_uses_deploy_user_except_for_admin() -> None:
    jump = make_node(
        "edge",
        role="bastion",
        ssh_user="keeper",
        admin_user=None,
    )

    assert (
        hop_user(
            jump,
            "ci",
            CONTROL,
        )
        == "github_actions"
    )
    assert (
        hop_user(
            jump,
            "deploy",
            CONTROL,
        )
        == "github_actions"
    )
    assert (
        hop_user(
            jump,
            "admin",
            CONTROL,
        )
        == "keeper"
    )


def test_admin_on_unmanaged_node_without_ssh_user_is_invalid() -> None:
    with pytest.raises(InvalidManifest):
        login_user(
            make_node(
                "edge",
                role="bastion",
                admin_user=None,
            ),
            "admin",
            CONTROL,
        )


def test_via_defaults_to_jump_when_configured() -> None:
    assert resolve_via(CONTROL, None) == "jump"
    assert resolve_via(ControlSection(), None) == "direct"
    with pytest.raises(UsageProblem):
        resolve_via(ControlSection(), "jump")


def test_direct_config_has_no_proxyjump_and_no_port_22() -> None:
    nodes = {
        "edge": make_node(
            "edge",
            role="bastion",
            ssh_port=22443,
        ),
        "nlA00": make_node("nlA00"),
    }

    text = render_ssh_config(
        nodes,
        CONTROL,
        "deploy",
        "direct",
        Path("/run/known_hosts"),
    )

    assert "ProxyJump" not in text
    assert "Port 22\n" not in text
    assert "Port 22443\n" in text


@pytest.mark.parametrize(
    "host_keys",
    [
        {"ed25519": "not-a-key"},
        {"rsa": ed25519_blob()},
        {"ed25519": _header_only_blob("ssh-ed25519")},
    ],
)
def test_malformed_or_mislabelled_host_key_is_invalid(host_keys: dict[str, str]) -> None:
    with pytest.raises(InvalidManifest):
        render_known_hosts({"nlA00": make_node("nlA00", host_keys=host_keys)})
