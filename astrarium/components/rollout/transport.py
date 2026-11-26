"""SSH transport: OpenSSH binaries against generated per-run config."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import random
import shutil
import tempfile
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from astrarium.components.sshcfg.render import JUMP_CONCURRENCY, SshPaths, Via, ssh_scope, write_ssh_files


if TYPE_CHECKING:
    from astrarium.components.manifest.derive import EffectiveNode
    from astrarium.components.manifest.models import ControlSection, Identity
    from astrarium.runtime import RuntimeDir

LOG = logging.getLogger(__name__)

TRANSPORT_FAILURE = 255
"""ssh/scp exit code for connection failures, also returned for local timeout."""

RETRY_DELAY = 5.0
"""Default backoff base, module attribute so tests can shorten it."""

_JITTER = random.SystemRandom()


def default_transport(paths: SshPaths, jumped: frozenset[str]) -> Transport:
    return OpenSshTransport(paths, jumped=jumped)


@dataclass(frozen=True)
class CommandResult:
    rc: int
    stdout: str
    stderr: str


class Transport(Protocol):
    """Remote command runner keyed by node id."""

    async def run(
        self,
        node_id: str,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> CommandResult: ...

    async def upload(self, node_id: str, files: Mapping[str, Path], remote_dir: str) -> CommandResult: ...


class OpenSshTransport:
    """`ssh -F <config> <id> <command>` and one `scp -F <config>` per upload, jumped nodes share concurrency cap.

    Node ids outside `paths.nodes` raise ValueError (no host entry, no DNS fallback).
    """

    def __init__(self, paths: SshPaths, *, jumped: frozenset[str], jump_limit: int = JUMP_CONCURRENCY) -> None:
        self.paths = paths
        self.jumped = jumped
        self._slots = asyncio.Semaphore(jump_limit)

    async def run(
        self,
        node_id: str,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        self._require_scope(node_id)
        argv = [
            "ssh",
            "-F",
            str(self.paths.config),
            node_id,
            command,
        ]
        return await self._exec(
            node_id,
            argv,
            stdin,
            timeout,
        )

    async def upload(self, node_id: str, files: Mapping[str, Path], remote_dir: str) -> CommandResult:
        """Hard-link (or copy) files into private temp dir under their mapping names, one scp call."""

        self._require_scope(node_id)
        with tempfile.TemporaryDirectory(dir=self.paths.config.parent) as tmp:
            sources = []
            for name, source in files.items():
                if not name or "/" in name or name in (".", ".."):
                    raise ValueError(f"invalid remote file name {name!r}")
                target = Path(tmp) / name
                try:
                    os.link(source, target)
                except OSError:
                    shutil.copyfile(source, target)
                    shutil.copymode(source, target)
                sources.append(str(target))
            argv = [
                "scp",
                "-F",
                str(self.paths.config),
                "-q",
                *sources,
                f"{node_id}:{remote_dir}/",
            ]
            return await self._exec(
                node_id,
                argv,
                None,
                None,
            )

    def _require_scope(self, node_id: str) -> None:
        if node_id not in self.paths.nodes:
            raise ValueError(f"node {node_id!r} is outside generated ssh config")

    async def _exec(self, node_id: str, argv: list[str], stdin: bytes | None, timeout: float | None) -> CommandResult:
        """Run argv, jumped node_id serialized through shared slot semaphore, no connection reuse."""

        slot = self._slots if node_id in self.jumped else contextlib.nullcontext()
        async with slot:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(stdin), timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return CommandResult(
                    TRANSPORT_FAILURE,
                    "",
                    "timed out",
                )
        rc = proc.returncode if proc.returncode is not None else TRANSPORT_FAILURE
        return CommandResult(
            rc,
            out.decode(errors="replace"),
            err.decode(errors="replace"),
        )


def write_scoped_ssh(
    runtime: RuntimeDir,
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    identity: Identity,
    via: Via,
    *,
    wanted: Iterable[str],
) -> tuple[SshPaths, frozenset[str]]:
    """SSH files for identity's route over ssh_scope of wanted, every scoped node jumped when via is jump."""

    scope = ssh_scope(
        nodes,
        wanted,
        control,
        via,
    )
    paths = write_ssh_files(
        runtime,
        scope,
        control,
        identity,
        via,
    )
    jumped = frozenset(scope) if via == "jump" else frozenset()
    return paths, jumped


def open_deploy_transport(
    runtime: RuntimeDir,
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    via: Via,
    make_transport: Callable[[SshPaths, frozenset[str]], Transport],
    *,
    wanted: Iterable[str],
) -> Transport:
    """Deploy-identity transport over ssh_scope of wanted, every scoped node jumped when via is jump."""

    paths, jumped = write_scoped_ssh(
        runtime,
        nodes,
        control,
        "deploy",
        via,
        wanted=wanted,
    )
    return make_transport(paths, jumped)


async def with_retries(
    call: Callable[[], Awaitable[CommandResult]],
    *,
    attempts: int = 3,
    base_delay: float = 5.0,
    retry_rcs: frozenset[int] = frozenset({TRANSPORT_FAILURE}),
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> CommandResult:
    """Retry result with exponential backoff plus jitter when rc in retry_rcs, attempts calls total."""

    result = await call()
    for attempt in range(1, attempts):
        if result.rc not in retry_rcs:
            return result
        LOG.warning(
            f"transport rc {result.rc} on attempt {attempt}/{attempts}, retrying",
        )
        await sleep(base_delay * 2 ** (attempt - 1) + _JITTER.uniform(0, base_delay))
        result = await call()
    return result
