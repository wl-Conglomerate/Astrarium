"""`arium fleet pdsh`: one remote command on every selected node, in parallel."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from astrarium.components.manifest.models import Identity
from astrarium.components.rollout.selection import select
from astrarium.components.rollout.transport import Transport, default_transport, write_scoped_ssh
from astrarium.components.sshcfg.render import SshPaths, Via, resolve_via
from astrarium.core import BaseController
from astrarium.errors import UsageProblem
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


DEFAULT_FANOUT = 32
"""pdsh default fanout."""

MAX_EXIT_CODE = 255
"""pdsh convention: exit code is failed-node count, capped at 255."""


@dataclass(frozen=True)
class PdshOptions:
    limit: str | None
    identity: Identity
    via: Via | None
    fanout: int = DEFAULT_FANOUT
    timeout: float | None = None
    dry_run: bool = False


@dataclass(frozen=True)
class NodeResult:
    node_id: str
    rc: int
    stdout: str
    stderr: str


@dataclass
class PdshReport:
    command: str
    via: Via
    targets: list[str]
    skipped: dict[str, str]
    results: list[NodeResult] = field(default_factory=list)


def pdsh_exit_code(results: Sequence[NodeResult]) -> int:
    """0 when every rc == 0, else failed-node count capped at 255 (pdsh failure-count convention)."""

    failed = sum(1 for result in results if result.rc != 0)
    return min(failed, MAX_EXIT_CODE) if failed else 0


def collapse_groups(results: Sequence[NodeResult]) -> list[tuple[list[str], NodeResult]]:
    """dshbak-style grouping: nodes with identical (rc, stdout, stderr) share one group, first-seen order."""

    groups: dict[tuple[int, str, str], tuple[list[str], NodeResult]] = {}
    for result in results:
        key = (
            result.rc,
            result.stdout,
            result.stderr,
        )
        if key in groups:
            groups[key][0].append(result.node_id)
        else:
            groups[key] = ([result.node_id], result)
    return list(groups.values())


class PdshController(BaseController["AstrariumApp"]):
    """Run one command per selected node over generated ssh files, results masked."""

    def __init__(self, app: AstrariumApp) -> None:
        super().__init__(app)
        self.make_transport: Callable[[SshPaths, frozenset[str]], Transport] = default_transport

    async def run(self, command: str, opts: PdshOptions) -> PdshReport:
        """Run `command` on selected nodes, results in selection order. Dry run resolves targets only."""

        if not command.strip():
            raise UsageProblem("no command given", hint="pass remote command after options (interactive mode off)")
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            selection = select(
                ctx.nodes,
                opts.limit,
                hexrift_only=False,
            )
            via = resolve_via(ctx.manifest.control, opts.via)
            if opts.dry_run or not selection.nodes:
                return PdshReport(
                    command=command,
                    via=via,
                    targets=list(selection.nodes),
                    skipped=dict(selection.skipped),
                )
            paths, jumped = write_scoped_ssh(
                runtime,
                ctx.nodes,
                ctx.manifest.control,
                opts.identity,
                via,
                wanted=selection.nodes,
            )
            transport = self.make_transport(paths, jumped)
            slots = asyncio.Semaphore(opts.fanout)

            async def one(node_id: str) -> NodeResult:
                async with slots:
                    outcome = await transport.run(
                        node_id,
                        command,
                        timeout=opts.timeout,
                    )
                return NodeResult(
                    node_id=node_id,
                    rc=outcome.rc,
                    stdout=ctx.masker.mask(outcome.stdout),
                    stderr=ctx.masker.mask(outcome.stderr),
                )

            results = await asyncio.gather(*(one(node_id) for node_id in selection.nodes))
            return PdshReport(
                command=command,
                via=via,
                targets=list(selection.nodes),
                skipped=dict(selection.skipped),
                results=list(results),
            )
