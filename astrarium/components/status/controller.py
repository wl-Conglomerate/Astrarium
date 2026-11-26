"""Read-only fleet status: reachability and built-vs-live config."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from astrarium.components.rollout.artifacts import sha256_file
from astrarium.components.rollout.outcomes import UNREACHABLE
from astrarium.components.rollout.plan import haproxy_installed
from astrarium.components.rollout.probe import LiveState, probe, reachable
from astrarium.components.rollout.selection import select
from astrarium.components.rollout.transport import Transport, default_transport, open_deploy_transport
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.sshcfg.render import SshPaths, Via, resolve_via
from astrarium.components.topology.bridge import BuiltNode
from astrarium.components.topology.controller import BuildContext
from astrarium.components.versions.controller import status_versions
from astrarium.components.versions.probe import NO_HOST_KEYS
from astrarium.components.versions.report import status_entries
from astrarium.core import BaseController
from astrarium.errors import ExitCode
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


LOG = logging.getLogger(__name__)

MATCH = "match"

DIFFERS = "differs"

NO_KEY = "no key file"

NO_EXIT_KEY = "no exit key file"

UNKNOWN = "unknown"

NOT_APPLICABLE = "-"


@dataclass(frozen=True)
class StatusOptions:
    limit: str | None
    via: Via | None
    no_config: bool
    all: bool = False


@dataclass
class NodeStatus:
    node_id: str
    role: str
    region: str
    reachable: bool
    config: str
    versions: dict[str, str] = field(default_factory=dict)
    """Component -> installed version label (filled by versions part)."""
    mismatches: list[str] = field(default_factory=list)
    """Columns that differ from manifest (`config`, component names)."""


def status_exit_code(statuses: Mapping[str, NodeStatus]) -> ExitCode:
    """PARTIAL when any node is unreachable or mismatched."""

    bad = any(not s.reachable or s.mismatches for s in statuses.values())
    return ExitCode.PARTIAL if bad else ExitCode.OK


def config_state(built: BuiltNode | None, live: LiveState | None, *, installed: bool) -> str:
    """Built-vs-live config of hub/exit: match, differs, unknown (no usable probe)."""

    if built is None:
        return NO_KEY
    if live is None:
        return UNKNOWN
    same = live.config_sha == sha256_file(built.config_json)
    if installed:
        same = same and live.haproxy_sha == sha256_file(built.haproxy_cfg)
    return MATCH if same else DIFFERS


class StatusController(BaseController["AstrariumApp"]):
    """`arium fleet status`: never writes, locally or on nodes."""

    def __init__(self, app: AstrariumApp) -> None:
        super().__init__(app)
        self.make_transport: Callable[[SshPaths, frozenset[str]], Transport] = default_transport
        self.make_keystore: Callable[[], KeyStore] = lambda: KeyStore(self.app.repo, self.app.sops)

    async def collect(self, opts: StatusOptions) -> dict[str, NodeStatus]:
        """Status per selected node, parallel within jump cap, builds only nodes whose key files exist.

        Nodes without host_keys stay out of ssh scope (no known_hosts entry), reported as `no host keys`.
        """

        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=not opts.no_config)
            control = ctx.manifest.control
            selection = select(
                ctx.nodes,
                opts.limit,
                hexrift_only=False,
            )
            via = resolve_via(control, opts.via)
            keyless = {node_id for node_id in selection.nodes if not ctx.nodes[node_id].host_keys}
            scoped = [node_id for node_id in selection.nodes if node_id not in keyless]
            transport = open_deploy_transport(
                runtime,
                ctx.nodes,
                control,
                via,
                self.make_transport,
                wanted=scoped,
            )
            built, no_key = (
                ({}, {})
                if opts.no_config
                else self._build_available(
                    ctx,
                    scoped,
                    runtime,
                )
            )
            probed = [n for n in scoped if ctx.nodes[n].is_hexrift and not opts.no_config]
            lives = dict(
                zip(
                    probed,
                    await asyncio.gather(*(probe(transport, n) for n in probed)),
                    strict=True,
                )
            )
            others = [n for n in scoped if n not in lives]
            reached = dict(
                zip(
                    others,
                    await asyncio.gather(*(reachable(transport, n) for n in others)),
                    strict=True,
                )
            )
            statuses: dict[str, NodeStatus] = {}
            for node_id in selection.nodes:
                node = ctx.nodes[node_id]
                if node_id in keyless:
                    statuses[node_id] = NodeStatus(
                        node_id,
                        node.role,
                        node.region,
                        False,
                        NO_HOST_KEYS,
                    )
                    continue
                config = NOT_APPLICABLE
                if node_id in lives:
                    live = lives[node_id]
                    state = live if isinstance(live, LiveState) else None
                    if state is None and live != UNREACHABLE:
                        LOG.warning(
                            f"{node_id}: probe failed: {ctx.masker.mask(str(live))}",
                        )
                    if node_id in no_key:
                        config = no_key[node_id]
                    else:
                        config = config_state(
                            built.get(node_id),
                            state,
                            installed=haproxy_installed(node),
                        )
                    up = live != UNREACHABLE
                else:
                    up = reached[node_id]
                status = NodeStatus(
                    node_id,
                    node.role,
                    node.region,
                    up,
                    config,
                )
                if up and config in (DIFFERS, UNKNOWN):
                    status.mismatches.append("config")
                statuses[node_id] = status
            await self.versions_part(
                ctx,
                transport,
                selection.nodes,
                statuses,
                all_components=opts.all,
            )
            return statuses

    async def versions_part(
        self,
        ctx: BuildContext,
        transport: Transport,
        node_ids: list[str],
        statuses: dict[str, NodeStatus],
        *,
        all_components: bool = False,
    ) -> None:
        """Installed-version columns for reachable nodes, `no host keys` cells for keyless ones."""

        shown_ids = [node_id for node_id in node_ids if statuses[node_id].reachable or not ctx.nodes[node_id].host_keys]
        cells = await status_versions(
            transport,
            ctx.nodes,
            ctx.manifest,
            self.app.repo.lockfile,
            shown_ids,
            all_components=all_components,
            masker=ctx.masker,
        )
        for node_id, node_cells in cells.items():
            shown, mismatched = status_entries(node_cells)
            statuses[node_id].versions.update(shown)
            statuses[node_id].mismatches.extend(mismatched)

    def _build_available(
        self,
        ctx: BuildContext,
        selected: list[str],
        runtime: RuntimeDir,
    ) -> tuple[dict[str, BuiltNode], dict[str, str]]:
        """Buildable hub/exit nodes, no-key reasons for others (missing key file, hub blocked by missing exit key)."""

        hexrift_ids = [node_id for node_id, node in ctx.nodes.items() if node.is_hexrift]
        missing = set(self.make_keystore().missing(hexrift_ids))
        exits_missing = any(ctx.nodes[node_id].root_role == "exit" for node_id in missing)
        no_key: dict[str, str] = {}
        buildable: list[str] = []
        for node_id in selected:
            node = ctx.nodes[node_id]
            if not node.is_hexrift:
                continue
            if node_id in missing:
                no_key[node_id] = NO_KEY
            elif node.root_role != "exit" and exits_missing:
                no_key[node_id] = NO_EXIT_KEY
            else:
                buildable.append(node_id)
        built = (
            self.app.topology.build(
                ctx,
                buildable,
                runtime.sub("build"),
            )
            if buildable
            else {}
        )
        return built, no_key
