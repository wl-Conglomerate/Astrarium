"""Scripted Transport: answers probe, stage, upload, launch, reconcile and small commands per node."""

from __future__ import annotations

import shlex
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from astrarium.components.rollout.probe import PROBE_MARKER
from astrarium.components.rollout.transport import CommandResult


DEFAULT_VERSION = "Xray 26.3.27 (Xray, Penetrates Everything.) 1a2b3c4 (go1.25.1 linux/amd64)"


def _run(command: str) -> str:
    return shlex.split(command.replace('"$HOME', '"/home/deploy'))[-1].split("/runs/")[1].split("/")[0]


@dataclass
class ScriptedNode:
    """Live facts of one fake node and answers it gives."""

    config_sha: str | None = "0" * 64
    haproxy_sha: str | None = None
    xray_sha: str | None = "1" * 64
    version: str = DEFAULT_VERSION
    arch: str = "x86_64"
    commit: str | None = None
    config_text: str = "{}\n"
    verdicts: list[str] = field(default_factory=lambda: ["applied"])
    unreachable: bool = False
    upload_rc: int = 0
    launch_rc: int = 0
    launch_stdout: str = "launched\n"
    reconcile_rc: int = 0
    healthy: bool = True


class FakeTransport:
    """Transport stand-in over ScriptedNode per node id, records every call.

    `scope`, set by wire_fakes from real deploy scope, makes run/upload raise ValueError for node
    id outside it, same fail-closed contract as OpenSshTransport.
    """

    def commands(self, node_id: str, word: str) -> list[str]:
        return [cmd for nid, cmd in self.calls if nid == node_id and word in cmd]

    @staticmethod
    def _probe(node: ScriptedNode) -> str:
        return (
            "\n".join(
                [
                    PROBE_MARKER,
                    f"config {node.config_sha or '-'}",
                    f"haproxy {node.haproxy_sha or '-'}",
                    f"xray {node.xray_sha or '-'}",
                    f"version {node.version or '-'}",
                    f"arch {node.arch}",
                    f"commit {node.commit or '-'}",
                ]
            )
            + "\n"
        )

    def __init__(self, nodes: dict[str, ScriptedNode]) -> None:
        self.nodes = nodes
        self.scope: frozenset[str] | None = None
        self.calls: list[tuple[str, str]] = []
        self.stdins: list[bytes | None] = []
        self.uploads: list[tuple[str, list[str], str]] = []

    def _require_scope(self, node_id: str) -> None:
        if self.scope is not None and node_id not in self.scope:
            raise ValueError(f"node {node_id!r} is outside generated ssh config")

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
        self.stdins.append(stdin)
        node = self.nodes[node_id]
        if node.unreachable:
            return CommandResult(
                255,
                "",
                "unreachable",
            )
        if stdin is not None and PROBE_MARKER.encode() in stdin:
            return CommandResult(
                0,
                self._probe(node),
                "",
            )
        if "mktemp -d" in command:
            return CommandResult(
                0,
                f"/home/deploy/.astrarium/runs/{_run(command)}/stage.Ab12Cd34\n",
                "",
            )
        if " launch " in command:
            return CommandResult(
                node.launch_rc,
                node.launch_stdout,
                "",
            )
        if " reconcile " in command:
            verdict = node.verdicts.pop(0) if len(node.verdicts) > 1 else node.verdicts[0]
            return CommandResult(
                node.reconcile_rc,
                f"result={verdict}\n",
                "",
            )
        if command.startswith("cat -- "):
            return CommandResult(
                0,
                node.config_text,
                "",
            )
        if command.startswith(("tail ", "rm -rf")) or command == "true":
            return CommandResult(
                0,
                "",
                "",
            )
        if "systemctl is-active" in command:
            return CommandResult(
                0 if node.healthy else 3,
                "",
                "",
            )
        if command.startswith("bash -c"):
            return CommandResult(
                0,
                "updated\n",
                "",
            )
        if "@@astrarium " in command:
            return CommandResult(
                0,
                "",
                "",
            )
        raise AssertionError(f"unexpected command for {node_id}: {command}")

    async def upload(self, node_id: str, files: Mapping[str, Path], remote_dir: str) -> CommandResult:
        self._require_scope(node_id)
        node = self.nodes[node_id]
        self.uploads.append(
            (
                node_id,
                sorted(files),
                remote_dir,
            )
        )
        return CommandResult(
            255 if node.unreachable else node.upload_rc,
            "",
            "",
        )
