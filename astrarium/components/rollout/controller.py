"""Deploy orchestration: plan, confirm, apply, report."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from hexrift.errors import Error as HexRiftError

from astrarium.components.manifest.models import Arch, DiscordNotify
from astrarium.components.rollout.ancestry import descends_from_many, head_commit_of
from astrarium.components.rollout.artifacts import ArtifactResolver, sha256_file
from astrarium.components.rollout.orrery import stripped_topology, upload_topology
from astrarium.components.rollout.outcomes import (
    CANARY_FAILED,
    OLDER_COMMIT,
    RECORDED_COMMIT_UNKNOWN,
    ROTATION_INCOMPLETE,
    WOULD_CHANGE,
    Outcome,
    Status,
)
from astrarium.components.rollout.plan import NodePlan, artifact_required, masked_diff, plan_node
from astrarium.components.rollout.probe import HAPROXY_CONFIG, XRAY_CONFIG, LiveState, fetch_file, probe
from astrarium.components.rollout.report import RunLog, new_run_id
from astrarium.components.rollout.runner import DEFAULT_SETTLE, ApplyParams, apply_log_tail, apply_node, verify_node
from astrarium.components.rollout.schedule import Schedule, build_schedule, run_schedule
from astrarium.components.rollout.selection import Selection, parse_limit, select
from astrarium.components.rollout.transport import Transport, default_transport, open_deploy_transport
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.secrets.masking import secret_leaves
from astrarium.components.sshcfg.render import SshPaths, Via, resolve_via
from astrarium.components.topology.bridge import BuiltNode
from astrarium.components.topology.controller import BuildContext
from astrarium.components.versions.upstream import UpstreamClient
from astrarium.core import BaseController
from astrarium.errors import ExternalToolError, Refused, UsageProblem
from astrarium.repo import ensure_clean
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


LOG = logging.getLogger(__name__)

DECLINED = Outcome(Status.NOT_ATTEMPTED, "declined")

ROTATION_WINDOW = "traffic through each rotated exit stops from its swap until every hub has reloaded (phase 2)"

ORRERY_RESTART = "Orrery before v0.3.0 reads the topology at start only: restart the collector"


def in_ci() -> bool:
    return os.environ.get("GITHUB_ACTIONS") == "true" or os.environ.get("CI") == "true"


@dataclass(frozen=True)
class DeployOptions:
    limit: str | None
    canary: str | None
    canary_wait: float
    stagger: float
    force: bool
    dry_run: bool
    via: Via | None
    artifacts: dict[Arch, Path]
    rotate_exit_keys: bool
    allow_dirty: bool
    notify: bool


@dataclass(frozen=True)
class DeployPlan:
    run_id: str
    commit: str
    via: Via
    plans: dict[str, NodePlan]
    settled: dict[str, Outcome]
    """Nodes decided at plan time: UNCHANGED, SKIPPED or FAILED."""
    phases: list[Schedule]
    rotate: list[str]
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DeployReport:
    plan: DeployPlan
    outcomes: dict[str, Outcome]
    applied: bool
    log_path: Path
    orrery: str | None
    notified: int | None
    notes: list[str] = field(default_factory=list)
    """Apply-time notes: rotation gate, Orrery restart."""


class RolloutController(BaseController["AstrariumApp"]):
    """Config and xray binary rollout."""

    async def deploy(self, opts: DeployOptions) -> dict[str, Outcome]:
        return (await self.run(opts)).outcomes

    def __init__(self, app: AstrariumApp) -> None:
        super().__init__(app)
        self.make_transport: Callable[[SshPaths, frozenset[str]], Transport] = default_transport
        self.make_upstream: Callable[[Path], UpstreamClient] = lambda cache: UpstreamClient(
            cache, os.environ.get("GITHUB_TOKEN")
        )
        self.make_keystore: Callable[[], KeyStore] = lambda: KeyStore(self.app.repo, self.app.sops)

    async def run(self, opts: DeployOptions, *, confirm: Callable[[DeployPlan], bool] | None = None) -> DeployReport:
        """Plan, show via confirm (False stops), apply unless dry run, upload Orrery topology, notify."""

        repo = self.app.repo
        self._guard(opts)
        ensure_clean(repo, allow_dirty=opts.allow_dirty or opts.dry_run)
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=True)
            discord = self._discord(ctx, opts)
            run_id = new_run_id()
            log = RunLog(
                repo,
                run_id,
                ctx.masker,
            )
            commit = head_commit_of(repo.root)
            selection = select(
                ctx.nodes,
                opts.limit,
                hexrift_only=True,
            )
            if opts.canary is not None and opts.canary not in selection.nodes:
                raise UsageProblem(f"canary {opts.canary} is not among the selected HexRift nodes")
            rotate, notes = self._rotation(
                ctx,
                selection,
                opts,
            )
            self.app.topology.require_keys(ctx, selection.nodes)
            if rotate:
                self._regenerate_exit_keys(ctx, rotate)
            built = (
                self.app.topology.build(
                    ctx,
                    selection.nodes,
                    runtime.sub("build"),
                )
                if selection.nodes
                else {}
            )
            via = resolve_via(ctx.manifest.control, opts.via)
            orrery_control = ctx.manifest.control.orrery
            wanted = list(selection.nodes)
            if orrery_control is not None and orrery_control.host in ctx.nodes:
                wanted.append(orrery_control.host)
            transport = open_deploy_transport(
                runtime,
                ctx.nodes,
                ctx.manifest.control,
                via,
                self.make_transport,
                wanted=wanted,
            )
            plan = await self._plan(
                ctx,
                selection,
                built,
                transport,
                opts,
                run_id,
                commit,
                via,
                rotate,
                notes,
            )
            self._check_rotation_covered(
                ctx,
                plan,
                rotate,
            )
            self._log_plan(
                log,
                plan,
                opts,
            )
            proceed = confirm(plan) if confirm is not None else True
            if opts.dry_run or not proceed:
                tail = await self._dry_run_outcomes(plan) if opts.dry_run else dict.fromkeys(plan.plans, DECLINED)
                outcomes = {**plan.settled, **tail}
                return DeployReport(
                    plan,
                    outcomes,
                    False,
                    log.path,
                    None,
                    None,
                )
            if rotate:
                store = self.make_keystore()
                for exit_id in rotate:
                    store.store(exit_id, self._key_file(ctx, exit_id))
                log.write(f"stored rotated exit keys: {', '.join(rotate)}")
            outcomes, notes = await self._apply(
                plan,
                transport,
                opts,
                ctx,
                log,
            )
            orrery = await self._orrery(
                ctx,
                transport,
                log,
            )
            if orrery == "updated":
                notes.append(ORRERY_RESTART)
            notified = None
            if discord is not None:
                notified = self._notify(
                    discord,
                    plan,
                    outcomes,
                    opts,
                    orrery,
                    runtime,
                )
                log.write(f"discord: HTTP {notified}")
                if notified and not 200 <= notified < 300:  # 0: network error, warned by sender
                    LOG.warning(f"discord summary not delivered: HTTP {notified}")
            return DeployReport(
                plan,
                outcomes,
                True,
                log.path,
                orrery,
                notified,
                notes,
            )

    @staticmethod
    def _guard(opts: DeployOptions) -> None:
        if opts.rotate_exit_keys and in_ci():
            raise Refused("--rotate-exit-keys runs from a laptop only")
        if opts.rotate_exit_keys and opts.canary is not None:
            raise UsageProblem("--rotate-exit-keys cannot be combined with --canary")

    @staticmethod
    def _discord(ctx: BuildContext, opts: DeployOptions) -> DiscordNotify | None:
        if not opts.notify:
            return None
        discord = ctx.manifest.notify.discord
        if discord is None or not discord.webhook_url:
            raise UsageProblem("--notify discord needs notify.discord.webhook_url in the secrets overlay")
        return discord

    @staticmethod
    def _rotation(ctx: BuildContext, selection: Selection, opts: DeployOptions) -> tuple[list[str], list[str]]:
        """Exits to rotate plus plan notes: explicit --rotate-exit-keys, else full-deploy policy on full run.

        --canary or --limit run under full-deploy policy skips rotation but says so in plan,
        never silently.
        """

        policy = ctx.manifest.keys.exit_rotation == "full-deploy"
        if in_ci():
            return [], (["CI ignores keys.exit_rotation: full-deploy"] if policy else [])
        limited = bool(parse_limit(opts.limit)) or opts.canary is not None
        if not opts.rotate_exit_keys:
            if not policy:
                return [], []
            if limited:
                return [], ["keys.exit_rotation: full-deploy skipped, this is a --canary or --limit run"]
        exits = [node_id for node_id in selection.nodes if ctx.nodes[node_id].root_role == "exit"]
        hubs = {node_id for node_id, node in ctx.nodes.items() if node.is_hexrift and node.root_role == "hub"}
        missing = sorted(hubs - set(selection.nodes))
        if missing:
            raise Refused(f"exit key rotation must redeploy every hub, not selected: {', '.join(missing)}")
        if not exits:
            raise UsageProblem("exit key rotation needs at least one selected exit")
        return exits, [f"rotating exit keys of {', '.join(exits)}: {ROTATION_WINDOW}"]

    @staticmethod
    def _check_rotation_covered(ctx: BuildContext, plan: DeployPlan, rotate: list[str]) -> None:
        """Refuse rotation when rotated exit or required hub was settled, not planned.

        `rotate` is decided before probing, so since-unreachable exit or hub stuck on older
        commit can still be in it. Storing new key or running other phase without such node
        would leave traffic through rotated-but-undeployed exit down until separate deploy
        catches it up.
        """

        if not rotate:
            return
        hubs = [node_id for node_id, node in ctx.nodes.items() if node.is_hexrift and node.root_role == "hub"]
        unsettled = [node_id for node_id in (*rotate, *hubs) if node_id not in plan.plans]
        if unsettled:
            raise Refused(
                f"exit key rotation needs {', '.join(unsettled)} to deploy in this run, already settled at plan time",
                hint="retry once they are reachable, or rerun without rotation",
            )

    @staticmethod
    def _key_file(ctx: BuildContext, node_id: str) -> Path:
        if ctx.keys_dir is None:
            raise ExternalToolError("key files were not decrypted")
        return ctx.keys_dir / f"{node_id}.yaml"

    def _regenerate_exit_keys(self, ctx: BuildContext, exits: list[str]) -> None:
        """HexRift gen_keys(force=True) on exits only, rotated values masked before any diff renders."""

        for exit_id in exits:
            key_file = self._key_file(ctx, exit_id)
            try:
                ctx.app.keys.gen_keys(
                    exit_id,
                    key_file.parent,
                    force=True,
                )
            except HexRiftError as e:
                raise ExternalToolError(ctx.masker.mask(f"key rotation for {exit_id} failed: {e}")) from None
            ctx.masker.add_many(secret_leaves(yaml.safe_load(key_file.read_text(encoding="utf-8"))))

    async def _dry_run_outcomes(self, plan: DeployPlan) -> dict[str, Outcome]:
        """Preview outcomes through same schedule shape apply uses, no transport touched.

        canary_wait=0 and verify=None: dry run never soaks canary or checks its health, WOULD_CHANGE
        (status OK) would otherwise trigger both.
        """

        async def would_change(node_id: str) -> Outcome:
            return WOULD_CHANGE

        outcomes: dict[str, Outcome] = {}
        for phase in plan.phases:
            outcomes.update(
                await run_schedule(
                    phase,
                    would_change,
                    stagger=0.0,
                    canary_wait=0.0,
                    verify=None,
                )
            )
        return outcomes

    async def _plan(
        self,
        ctx: BuildContext,
        selection: Selection,
        built: Mapping[str, BuiltNode],
        transport: Transport,
        opts: DeployOptions,
        run_id: str,
        commit: str,
        via: Via,
        rotate: list[str],
        notes: list[str],
    ) -> DeployPlan:
        notes = [*notes]
        settled: dict[str, Outcome] = {
            node_id: Outcome(Status.SKIPPED, why) for node_id, why in selection.skipped.items()
        }
        lives = await asyncio.gather(*(probe(transport, node_id) for node_id in selection.nodes))
        resolver = ArtifactResolver(
            self.make_upstream(self.app.repo.cache_dir),
            self.app.repo.cache_dir,
            ctx.runtime,
        )
        recorded = {
            live.recorded_commit
            for live in lives
            if isinstance(live, LiveState) and live.recorded_commit and not opts.force
        }
        ancestry = descends_from_many(
            self.app.repo.root,
            recorded,
            commit,
        )
        plans: dict[str, NodePlan] = {}
        pending: list[tuple[str, LiveState, Any, BuiltNode, bool]] = []
        for node_id, live in zip(
            selection.nodes,
            lives,
            strict=True,
        ):
            node = ctx.nodes[node_id]
            if not isinstance(live, LiveState):
                settled[node_id] = live
                continue
            if not opts.force and live.recorded_commit:
                descends = ancestry.get(live.recorded_commit)
                if descends is None:
                    settled[node_id] = RECORDED_COMMIT_UNKNOWN
                    notes.append(
                        f"{node_id}: recorded commit {live.recorded_commit[:12]} is unknown here, node not deployed: "
                        "git fetch and retry, or retry with --force when that commit is gone"
                        f" (`arium fleet deploy --force --limit {node_id}`)"
                    )
                    continue
                if not descends:
                    settled[node_id] = OLDER_COMMIT
                    continue
            pin = node.versions.get("xray")
            artifact = None
            needed = artifact_required(
                pin,
                live,
                node.arch,
                opts.artifacts,
            )
            if pin is not None and live.xray_sha is not None and needed:
                artifact = resolver.resolve(
                    pin,
                    node.arch,
                    opts.artifacts,
                )
            new = built[node_id]
            differs = live.config_sha is not None and live.config_sha != sha256_file(new.config_json)
            pending.append(
                (
                    node_id,
                    live,
                    artifact,
                    new,
                    differs,
                )
            )
        fetch_ids = [node_id for node_id, _, _, _, differs in pending if differs]
        fetched = dict(
            zip(
                fetch_ids,
                await asyncio.gather(
                    *(
                        fetch_file(
                            transport,
                            node_id,
                            XRAY_CONFIG,
                        )
                        for node_id in fetch_ids
                    )
                ),
                strict=True,
            )
        )
        haproxy_old: dict[str, str | None] = {}
        haproxy_paths: dict[str, Path] = {}
        for node_id, live, artifact, new, differs in pending:
            node = ctx.nodes[node_id]
            result = plan_node(
                node,
                new,
                live,
                artifact,
                force=opts.force,
                masker=ctx.masker,
                live_config_text=fetched.get(node_id) if differs else None,
            )
            if isinstance(result, Outcome):
                settled[node_id] = result
                continue
            if result.haproxy is not None and live.haproxy_sha != sha256_file(result.haproxy):
                haproxy_old[node_id] = None
                haproxy_paths[node_id] = result.haproxy
            plans[node_id] = result
        live_by_id = {node_id: live for node_id, live, _, _, _ in pending}
        hop_fetch = [node_id for node_id in haproxy_old if live_by_id[node_id].haproxy_sha]
        hop_fetched = dict(
            zip(
                hop_fetch,
                await asyncio.gather(
                    *(
                        fetch_file(
                            transport,
                            node_id,
                            HAPROXY_CONFIG,
                        )
                        for node_id in hop_fetch
                    )
                ),
                strict=True,
            )
        )
        haproxy_old.update(hop_fetched)
        for node_id, old in haproxy_old.items():
            result = plans[node_id]
            extra = masked_diff(
                "haproxy.cfg",
                old,
                haproxy_paths[node_id].read_text(),
                ctx.masker,
                kind="haproxy",
            )
            plans[node_id] = replace(result, diff=result.diff + extra)
        if opts.canary is not None and settled.get(opts.canary, Outcome(Status.OK)).status is Status.FAILED:
            settled.update(dict.fromkeys(plans, CANARY_FAILED))
            plans = {}
        if opts.canary is not None and opts.canary not in plans and plans:
            notes.append(
                f"canary {opts.canary} is {settled[opts.canary]} at plan time: "
                "canary gate skipped, planned nodes deploy without it"
            )
        return DeployPlan(
            run_id=run_id,
            commit=commit,
            via=via,
            plans=plans,
            settled=settled,
            phases=self._phases(
                ctx,
                plans,
                opts,
                rotate,
            ),
            rotate=rotate,
            notes=notes,
        )

    @staticmethod
    def _phases(
        ctx: BuildContext,
        plans: Mapping[str, NodePlan],
        opts: DeployOptions,
        rotate: list[str],
    ) -> list[Schedule]:
        jump = ctx.manifest.control.jump
        if not rotate:
            canary = opts.canary if opts.canary in plans else None
            return [
                build_schedule(
                    Selection(list(plans), {}),
                    ctx.nodes,
                    canary,
                    jump,
                )
            ]
        exits = [node_id for node_id in plans if ctx.nodes[node_id].root_role == "exit"]
        hubs = [node_id for node_id in plans if ctx.nodes[node_id].root_role != "exit"]
        return [
            build_schedule(
                Selection(exits, {}),
                ctx.nodes,
                None,
                jump,
            ),
            build_schedule(
                Selection(hubs, {}),
                ctx.nodes,
                None,
                jump,
            ),
        ]

    @staticmethod
    def _log_plan(log: RunLog, plan: DeployPlan, opts: DeployOptions) -> None:
        log.write(f"run {plan.run_id} commit {plan.commit} via {plan.via} dry_run={opts.dry_run} force={opts.force}")
        for note in plan.notes:
            log.write(note)
        for node_id, outcome in plan.settled.items():
            log.write(f"{node_id}: {outcome} (at plan time)")
        for node_id, node_plan in plan.plans.items():
            binary = node_plan.binary.label if node_plan.binary else "-"
            log.write(
                f"{node_id}: config={'change' if node_plan.config else '-'} "
                f"haproxy={'change' if node_plan.haproxy else '-'} xray={binary}"
            )
            if node_plan.diff:
                log.write(node_plan.diff)

    async def _apply(
        self,
        plan: DeployPlan,
        transport: Transport,
        opts: DeployOptions,
        ctx: BuildContext,
        log: RunLog,
    ) -> tuple[dict[str, Outcome], list[str]]:
        """Outcomes per node plus run notes, phases after rotated exits run only when every one ended OK."""

        params = ApplyParams(
            run_id=plan.run_id,
            commit=plan.commit,
            settle=DEFAULT_SETTLE,
            force=opts.force,
            deploy_user=ctx.manifest.control.deploy_user,
        )

        async def one(node_id: str) -> Outcome:
            outcome = await apply_node(
                transport,
                plan.plans[node_id],
                params,
            )
            log.write(f"{node_id}: {outcome}")
            if outcome.status is Status.FAILED:
                log.write(
                    await apply_log_tail(
                        transport,
                        node_id,
                        plan.run_id,
                    )
                )
            return outcome

        async def verify(node_id: str) -> bool:
            node_plan = plan.plans[node_id]
            return await verify_node(
                transport,
                node_id,
                haproxy=node_plan.haproxy_installed and node_plan.haproxy_wanted,
            )

        outcomes = dict(plan.settled)
        notes: list[str] = []
        for number, phase in enumerate(plan.phases):
            failed = [] if number == 0 else [e for e in plan.rotate if outcomes[e].status is not Status.OK]
            if failed:
                outcomes.update(dict.fromkeys(_phase_nodes(phase), ROTATION_INCOMPLETE))
                note = (
                    f"exit rotation incomplete, {', '.join(failed)} did not apply new keys: hubs not redeployed, "
                    "new keys stay in secrets/keys/. Fix those exits and rerun `arium fleet deploy` "
                    "(commit secrets/keys/ first or pass --allow-dirty), "
                    "or restore old keys with `git checkout secrets/keys/` and run `arium fleet deploy`"
                )
                log.write(note)
                notes.append(note)
                continue
            outcomes.update(
                await run_schedule(
                    phase,
                    one,
                    stagger=opts.stagger,
                    canary_wait=opts.canary_wait,
                    verify=verify,
                    mask=ctx.masker.mask,
                )
            )
        return outcomes, notes

    async def _orrery(self, ctx: BuildContext, transport: Transport, log: RunLog) -> str | None:
        orrery = ctx.manifest.control.orrery
        if orrery is None:
            return None
        if orrery.host not in ctx.nodes:
            log.write(f"orrery host {orrery.host} is not a node")
            return "failed"
        result = await upload_topology(
            transport,
            orrery.host,
            orrery.topology_path,
            stripped_topology(ctx.hexrift),
            ctx.masker,
        )
        log.write(f"orrery topology on {orrery.host}: {result}")
        if result == "updated":
            log.write(ORRERY_RESTART)
        return result

    def _notify(
        self,
        discord: DiscordNotify,
        plan: DeployPlan,
        outcomes: Mapping[str, Outcome],
        opts: DeployOptions,
        orrery: str | None,
        runtime: RuntimeDir,
    ) -> int:
        scope = opts.limit or "all nodes"
        if opts.canary:
            scope += f" (canary {opts.canary})"
        extra = {"Orrery": orrery} if orrery else {}
        return self.app.notify.deploy_summary(
            discord,
            title="Deploy",
            outcomes=outcomes,
            scope=scope,
            commit=plan.commit,
            run_id=plan.run_id,
            extra=extra,
            summary_file=runtime.sub("notify") / "summary.txt",
        )


def _phase_nodes(phase: Schedule) -> list[str]:
    canary = [phase.canary] if phase.canary is not None else []
    return [
        *canary,
        *phase.alone,
        *(node_id for ids in phase.regions.values() for node_id in ids),
    ]
