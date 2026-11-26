"""Test builders: effective nodes, control sections, transports and cast stand-ins."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast

from nullforge.molds import FeaturesMold
from nullforge.smithy.versions import DEFAULT_VERSIONS

from astrarium.components.inventory.cast import CastResult
from astrarium.components.inventory.controller import InventoryController
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import HEXRIFT_ROLES, Arch, CiControl, ControlSection, Manifest, OrreryControl
from astrarium.components.rollout.transport import CommandResult
from astrarium.components.sshcfg.render import SshPaths


HOST_KEY = "AAAAC3NzaC1lZDI1NTE5AAAAIFGxoxp63BQCe2xiI9URI+a04uIp3yFrQBMtnBggAYRS"

OPERATOR_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBdjfJU6wRLEqMViaQxqQDVG30ws3gV5M432EnmEOSfb op-sample"

CI_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPr6d6w3ztr6jVFMocE5vhNkwmvy7AbCuUosLOC8zIBl ci-sample"

TELEMT_SECRET = "0123456789abcdef0123456789abcdef"

ROLE_FEATURES: dict[str, dict[str, Any]] = {
    "exit": {"xray": {"install": True}, "haproxy": {"install": True}},
    "hub": {
        "xray": {"install": True},
        "haproxy": {"install": True},
        "warp": {"install": True},
    },
    "pulsar": {
        "telemt": {
            "install": True,
            "tls_domain": "example.net",
            "users": {"alice": TELEMT_SECRET},
        }
    },
    "bastion": {"users": {"users": []}},
}

NO_LOCK = Path("/nonexistent/astrarium-test/uv.lock")


def features(**sections: dict[str, Any]) -> dict[str, Any]:
    return FeaturesMold.model_validate(sections).model_dump(mode="json")


def make_node(
    node_id: str,
    root_role: str = "exit",
    *,
    ipv4: str = "203.0.113.10",
    ipv6: str | None = None,
    ssh_port: int = 22,
    ssh_user: str | None = None,
    admin_user: str | None = "core",
    sections: dict[str, Any] | None = None,
    versions: dict[str, Any] | None = None,
    runes: list[str] | None = None,
    arch: Arch = "x86_64",
) -> EffectiveNode:
    return EffectiveNode(
        id=node_id,
        role=root_role,
        root_role=root_role,
        is_hexrift=root_role in HEXRIFT_ROLES,
        region=re.split(r"[^a-z]", node_id)[0],
        fqdn=f"{node_id.lower()}.example.net",
        system_hostname=node_id,
        ipv4=ipv4,
        ipv6=ipv6,
        arch=arch,
        ssh_port=ssh_port,
        ssh_user=ssh_user,
        admin_user=admin_user,
        host_keys={"ed25519": HOST_KEY},
        features=features(**(ROLE_FEATURES[root_role] if sections is None else sections)),
        system={},
        versions=dict(DEFAULT_VERSIONS) if versions is None else versions,
        runes=[] if runes is None else list(runes),
        provenance={},
    )


def make_control(
    *,
    ci: bool = True,
    jump: str | None = "edge",
    orrery_host: str | None = None,
    deploy_keys: list[str] | None = None,
) -> ControlSection:
    return ControlSection(
        deploy_user="github_actions",
        deploy_keys=[OPERATOR_KEY] if deploy_keys is None else deploy_keys,
        ci=CiControl(cast_user="astrarium_ci", cast_keys=[CI_KEY]) if ci else None,
        jump=jump,
        orrery=OrreryControl(host=orrery_host, topology_path="/srv/orrery/topology.yaml") if orrery_host else None,
    )


def fleet() -> dict[str, EffectiveNode]:
    """Jump bastion plus two exits, one hub and one pulsar."""

    nodes = [
        make_node(
            "edge",
            "bastion",
            ipv4="198.51.100.20",
            ipv6="2001:db8::20",
            ssh_port=22443,
            ssh_user="operator",
            admin_user=None,
        ),
        make_node(
            "nlA00",
            "exit",
            ipv4="203.0.113.10",
            ipv6="2001:db8::10",
        ),
        make_node(
            "nlA01",
            "exit",
            ipv4="203.0.113.11",
        ),
        make_node(
            "mskA10",
            "hub",
            ipv4="203.0.113.30",
        ),
        make_node(
            "plsA00",
            "pulsar",
            ipv4="203.0.113.40",
        ),
    ]
    return {node.id: node for node in nodes}


@dataclass
class ScriptedTransport:
    """Transport stand-in answering by (node id, command substring), records every call.

    `scope`, set by TransportPool.__call__ from paths.nodes, makes run/upload raise ValueError for
    node id outside it, same fail-closed contract as OpenSshTransport.
    """

    replies: dict[tuple[str, str], CommandResult] = field(default_factory=dict)
    calls: list[tuple[str, str]] = field(default_factory=list)
    scope: frozenset[str] | None = None

    async def run(
        self,
        node_id: str,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        self._require_scope(node_id)
        self.calls.append((node_id, command))
        for (node, needle), result in self.replies.items():
            if node == node_id and needle in command:
                return result
        return CommandResult(
            rc=0,
            stdout="",
            stderr="",
        )

    async def upload(self, node_id: str, files: Mapping[str, Path], remote_dir: str) -> CommandResult:
        self._require_scope(node_id)
        self.calls.append((node_id, f"upload {remote_dir}"))
        return CommandResult(
            rc=0,
            stdout="",
            stderr="",
        )

    def _require_scope(self, node_id: str) -> None:
        if self.scope is not None and node_id not in self.scope:
            raise ValueError(f"node {node_id!r} is outside generated ssh config")


@dataclass
class TransportPool:
    """make_transport stand-in: one ScriptedTransport per (identity, route), scoped to paths.nodes."""

    transports: dict[tuple[str, str], ScriptedTransport] = field(default_factory=dict)

    def get(self, identity: str, via: str) -> ScriptedTransport:
        return self.transports.setdefault((identity, via), ScriptedTransport())

    def open(self, identity: str, via: str) -> ScriptedTransport:
        return self.get(identity, via)

    def __call__(self, paths: SshPaths, jumped: frozenset[str]) -> ScriptedTransport:
        transport = self.get(paths.identity, paths.via)
        transport.scope = paths.nodes
        return transport


@dataclass
class FakeRunner:
    """CastRunner stand-in: script decides each result, calls recorded as (limits, runes, dry)."""

    script: Callable[[list[str], list[str]], CastResult] | None = None
    stderr_lines: list[str] = field(default_factory=list)
    calls: list[tuple[list[str], list[str], bool]] = field(default_factory=list)

    def run_streaming(
        self,
        inventory: Path,
        limits: list[str],
        runes: list[str],
        *,
        dry: bool,
        on_stderr: Callable[[str], None],
    ) -> CastResult:
        self.calls.append(
            (
                list(limits),
                list(runes),
                dry,
            )
        )
        for line in self.stderr_lines:
            on_stderr(line)
        if self.script is None:
            return CastResult(
                rc=0,
                failed_hosts=[],
                changed={},
                stages=1,
            )
        return self.script(list(limits), list(runes))


def manifest_from(
    nodes: Mapping[str, EffectiveNode],
    *,
    control: ControlSection | None = None,
    versions: dict[str, Any] | None = None,
    node_versions: dict[str, dict[str, Any]] | None = None,
    components: dict[str, Any] | None = None,
) -> Manifest:
    """Manifest whose nodes mirror effective nodes (role, addresses, arch, ssh, host key, version overrides)."""

    pins = {} if node_versions is None else node_versions
    return Manifest.model_validate(
        {
            "deployment": {
                "name": "test",
                "domain": "example.net",
                "names": {
                    "exit": "aphelion",
                    "hub": "perigee",
                    "pulsar": "pulsar",
                },
            },
            "control": (make_control() if control is None else control).model_dump(),
            "versions": {} if versions is None else versions,
            "components": {} if components is None else components,
            "nodes": {
                node.id: {
                    "role": node.role,
                    "ipv4": node.ipv4,
                    **({"ipv6": node.ipv6} if node.ipv6 else {}),
                    "arch": node.arch,
                    "ssh": {"port": node.ssh_port, "user": node.ssh_user},
                    "host_keys": dict(node.host_keys),
                    "overrides": {"versions": pins.get(node.id, {})},
                }
                for node in nodes.values()
            },
        }
    )


def controller_with(runner: FakeRunner, pool: TransportPool) -> InventoryController:
    """InventoryController on fakes, run_casts needs no application."""

    class _Controller(InventoryController):
        def make_runner(self) -> Any:
            return runner

        def make_transport(self, paths: SshPaths, jumped: frozenset[str]) -> Any:
            return pool(paths, jumped)

    return _Controller(cast(Any, None))
