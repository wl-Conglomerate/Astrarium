"""NullForge cast orchestration: batches of casts with lock checks, fresh-login checks and verification."""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING

from astrarium.components.inventory.access import access_data
from astrarium.components.inventory.batches import cast_batches
from astrarium.components.inventory.cast import CastRunner, check_limits, touches_ssh
from astrarium.components.inventory.paths import (
    CastIdentity,
    PathFailure,
    check_cast_identity,
    deploy_busy,
    paths_in_use,
    run_scoped_transports,
    verify_paths,
)
from astrarium.components.inventory.render import render_inventory, write_inventory
from astrarium.components.inventory.runes import repo_runes, resolve_rune
from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import ControlSection
from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.report import RunLog, new_run_id
from astrarium.components.rollout.schedule import build_schedule
from astrarium.components.rollout.selection import Selection, parse_limit, select
from astrarium.components.rollout.transport import Transport, default_transport
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.sshcfg.render import SshPaths, Via, resolve_via
from astrarium.components.versions.registry import build_registry, check_pins
from astrarium.core import BaseController
from astrarium.errors import ExternalToolError, Refused
from astrarium.repo import Repo, ensure_clean
from astrarium.runes import builtin_rune_path
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp

LOG = logging.getLogger(__name__)

LOG_TAIL = 40

DONE = frozenset({Status.OK, Status.UNCHANGED})

Stage = Mapping[str, tuple[str, ...]]
"""Rune arguments per node for one cast stage; () is full NullForge cast."""

Verifier = Callable[[list[str]], Awaitable[dict[str, str]]]
"""Check after batch: node id -> failure reason."""

VerifierFactory = Callable[[Transport], Verifier]
"""Builds Verifier bound to Transport run_casts already opened for cast identity and route,
so caller-side re-probe never writes its own second ssh-<identity>-<via> for same run."""


def preview_of(title: str, plan: CastPlan, skipped: Mapping[str, str]) -> CastPreview:
    return CastPreview(
        title=title,
        identity=plan.identity,
        via=plan.via,
        dry=plan.dry,
        stages=[stage_label(stage) for stage in plan.stages],
        batches=[list(batch) for batch in plan.batches],
        skipped=dict(skipped),
    )


@dataclass(frozen=True)
class CastPlan:
    batches: list[list[str]]
    stages: list[Stage]
    identity: CastIdentity
    via: Via
    canary: str | None
    canary_wait: float
    stagger: float
    dry: bool


@dataclass(frozen=True)
class CastReport:
    outcome: Outcome
    changed: list[str] = field(default_factory=list)
    log_tail: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CastPreview:
    title: str
    identity: CastIdentity
    via: Via
    dry: bool
    stages: list[str]
    batches: list[list[str]]
    skipped: dict[str, str]


@dataclass(frozen=True)
class ProvisionOptions:
    limit: str | None
    runes: list[str]
    dry_run: bool
    identity: CastIdentity
    via: Via | None
    canary: str | None
    canary_wait: float
    stagger: float
    allow_dirty: bool
    echo: Callable[[str], None] | None = None


@dataclass(frozen=True)
class ProvisionPlan:
    targets: list[str]
    skipped: dict[str, str]
    stages: list[Stage]


def bastion_skip(node: EffectiveNode, named: set[str], identity: CastIdentity) -> str | None:
    """Reason to leave bastion out: no CI cast user or root login there, and broad selections never reach it."""

    if node.root_role != "bastion":
        return None
    if identity == "ci":
        return "no CI cast user on a bastion"
    if identity == "root":
        return "bastions are never root-cast, hop there as admin"
    if node.id not in named:
        return "bastion: name it in --limit to cast it"
    return None


def check_targets(targets: Sequence[str], nodes: Mapping[str, EffectiveNode], control: ControlSection) -> None:
    """CastRunner.argv id checks and access data per target, run before ssh files and confirmation."""

    check_limits(targets)
    for node_id in targets:
        access_data(
            nodes[node_id],
            nodes,
            control,
        )


def plan_provision(
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    repo: Repo,
    *,
    limit: str | None,
    runes: Sequence[str],
    identity: CastIdentity,
) -> ProvisionPlan:
    """Targets, skipped nodes and cast stages of `arium fleet provision`."""

    selection = select(
        nodes,
        limit,
        hexrift_only=False,
    )
    named = set(parse_limit(limit))
    targets: list[str] = []
    skipped = dict(selection.skipped)
    for node_id in selection.nodes:
        reason = bastion_skip(
            nodes[node_id],
            named,
            identity,
        )
        if reason is None:
            targets.append(node_id)
        else:
            skipped[node_id] = reason
    if targets:
        check_targets(
            targets,
            nodes,
            control,
        )

    stages: list[Stage]
    if runes:
        chosen = tuple(resolve_rune(name, repo) for name in runes)
        stages = [{node_id: chosen for node_id in targets}]
    else:
        builtin = ["deploy_access", *(["ci_access"] if control.ci is not None else [])]
        common = [*builtin, *repo_runes(repo)]
        stages = [
            {node_id: () for node_id in targets},
            {
                node_id: tuple(resolve_rune(name, repo) for name in dict.fromkeys([*common, *nodes[node_id].runes]))
                for node_id in targets
            },
        ]

    orrery = control.orrery
    if orrery is not None and orrery.host in targets and nodes[orrery.host].root_role == "bastion":
        access = str(builtin_rune_path("deploy_access"))
        if any(access in stage[orrery.host] for stage in stages):
            raise Refused(
                f"jump-only deploy access on {orrery.host} would stop the Orrery topology upload",
                hint="cast other runes there with --rune, or drop control.orrery once NullForge runs the collector",
            )
    return ProvisionPlan(
        targets=targets,
        skipped=skipped,
        stages=stages,
    )


def stage_label(stage: Stage) -> str:
    """Label of one cast stage: full NullForge cast or rune names."""

    rune_sets = set(stage.values())
    if rune_sets <= {()}:
        return "full NullForge cast"
    names = sorted({Path(rune).stem if rune.endswith(".py") else rune for runes in rune_sets for rune in runes})
    return "runes " + ", ".join(names)


def log_cast_run(repo: Repo, kind: str, reports: Mapping[str, CastReport], masker: ValueMasker) -> Path:
    """Masked run log with outcome and changed op names per node, never raw cast output."""

    log = RunLog(
        repo,
        f"{kind}-{new_run_id()}",
        masker,
    )
    log.write(f"commit {repo.commit() or 'unknown'}")
    for node_id in sorted(reports):
        report = reports[node_id]
        log.write(
            " ".join(
                part
                for part in (
                    node_id,
                    report.outcome.status.value,
                    report.outcome.reason,
                )
                if part
            )
        )
        for name in report.changed:
            log.write(f"  changed: {name}")
    return log.path


def _path_failures(found: Sequence[PathFailure], jump: str | None) -> dict[str, str]:
    """Failed identity/route probe per node it failed for, jump of jump batch failed too when given."""

    failures: dict[str, str] = {}
    for failure in found:
        failures.setdefault(failure.node_id, f"ssh check failed: {failure.identity} via {failure.via}")
    if failures and jump is not None:
        failures.setdefault(jump, "hop check failed")
    return failures


def _cast_error(node_ids: Sequence[str], e: ExternalToolError, masker: ValueMasker) -> str:
    """Masked exception message, logged at warning and returned as failure reason."""

    reason = masker.mask(e.message)
    LOG.warning(
        f"cast failed for {', '.join(node_ids)}: {reason}",
    )
    return reason


class InventoryController(BaseController["AstrariumApp"]):
    """NullForge casts over generated inventory."""

    def make_transport(self, paths: SshPaths, jumped: frozenset[str]) -> Transport:
        return default_transport(paths, jumped)

    def make_runner(self) -> CastRunner:
        return CastRunner()

    async def run_casts(
        self,
        runtime: RuntimeDir,
        nodes: Mapping[str, EffectiveNode],
        control: ControlSection,
        plan: CastPlan,
        masker: ValueMasker,
        *,
        verify: VerifierFactory | None = None,
        echo: Callable[[str], None] | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> dict[str, CastReport]:
        """Cast plan batches in order, rest NOT_ATTEMPTED once canary or jump ends not DONE or SSH login breaks.

        `nodes` is whole fleet, run targets come from `plan.batches`, every identity/route opened once over
        them (plus jump) through run_scoped_transports. `verify` builds its Verifier from cast identity's
        own Transport, so caller-side re-probe shares run's ssh-<identity>-<via> files.
        """

        targets = sorted({node_id for batch in plan.batches for node_id in batch})
        runner = self.make_runner()
        open_transport = run_scoped_transports(
            runtime,
            nodes,
            control,
            self.make_transport,
            targets,
        )
        ssh, transport = open_transport(plan.identity, plan.via)
        inventory = write_inventory(
            runtime,
            render_inventory(
                {node_id: nodes[node_id] for node_id in targets},
                nodes,
                ssh,
                control,
            ),
        )
        checker = verify(transport) if verify is not None else None

        reports: dict[str, CastReport] = {}
        aborted: str | None = None
        for index, batch in enumerate(plan.batches):
            if aborted is not None:
                for node_id in batch:
                    reports.setdefault(node_id, CastReport(Outcome(Status.NOT_ATTEMPTED, aborted)))
                continue
            if index and not plan.dry:
                await sleep(plan.stagger)
            canary = plan.canary is not None and batch == [plan.canary]
            jump_batch = control.jump is not None and batch == [control.jump]
            live = list(batch)
            if not plan.dry:
                blocked = await deploy_busy(
                    transport,
                    live,
                    control.deploy_user,
                    masker,
                )
                reports.update({node_id: CastReport(outcome) for node_id, outcome in blocked.items()})
                live = [node_id for node_id in live if node_id not in blocked]
            if not live:
                if canary:
                    aborted = "canary not cast"
                elif jump_batch:
                    aborted = "jump not cast"
                continue
            batch_reports = await asyncio.to_thread(
                self._cast_batch,
                runner,
                inventory,
                live,
                plan,
                masker,
                echo,
            )
            reports.update(batch_reports)
            if plan.dry:
                continue
            done = [node_id for node_id in live if batch_reports[node_id].outcome.status in DONE]
            if not done:
                if canary:
                    aborted = "canary failed"
                elif jump_batch:
                    aborted = "jump failed"
                continue
            if canary:
                await sleep(plan.canary_wait)
            path_failures: dict[str, str] = {}
            if canary or touches_ssh({node_id: batch_reports[node_id].changed for node_id in done}, done):
                pairs = paths_in_use(
                    plan.identity,
                    plan.via,
                    control,
                )
                found = await verify_paths(
                    open_transport,
                    nodes,
                    pairs,
                    done,
                    jump_batch=jump_batch,
                )
                path_failures = _path_failures(found, batch[0] if jump_batch else None)
            checked = await checker(done) if checker is not None else {}
            for node_id, reason in {**checked, **path_failures}.items():
                outcome = Outcome(Status.FAILED, reason)
                previous = reports.get(node_id)
                reports[node_id] = replace(previous, outcome=outcome) if previous is not None else CastReport(outcome)
            if path_failures:
                aborted = "ssh path check failed"
            elif canary and checked:
                aborted = "canary verification failed"
            elif jump_batch and checked:
                aborted = "jump failed"
        return reports

    async def provision(
        self,
        opts: ProvisionOptions,
        confirm: Callable[[list[CastPreview]], bool],
    ) -> dict[str, CastReport] | None:
        """Full provision or given runes on selected nodes, None when confirmation is declined."""

        repo = self.app.repo
        ensure_clean(repo, allow_dirty=opts.allow_dirty or opts.dry_run)
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            control = ctx.manifest.control
            via = resolve_via(control, opts.via)
            check_cast_identity(
                opts.identity,
                via,
                control,
            )
            check_pins(ctx.manifest, build_registry(ctx.manifest, repo.lockfile))
            plan = plan_provision(
                ctx.nodes,
                control,
                repo,
                limit=opts.limit,
                runes=opts.runes,
                identity=opts.identity,
            )
            reports = {node_id: CastReport(Outcome(Status.SKIPPED, reason)) for node_id, reason in plan.skipped.items()}
            if not plan.targets:
                return reports
            schedule = build_schedule(
                Selection(nodes=plan.targets, skipped={}),
                ctx.nodes,
                opts.canary,
                control.jump,
            )
            cast_plan = CastPlan(
                batches=cast_batches(schedule),
                stages=plan.stages,
                identity=opts.identity,
                via=via,
                canary=opts.canary,
                canary_wait=opts.canary_wait,
                stagger=opts.stagger,
                dry=opts.dry_run,
            )
            if not confirm(
                [
                    preview_of(
                        "provision",
                        cast_plan,
                        plan.skipped,
                    )
                ]
            ):
                return None
            reports.update(
                await self.run_casts(
                    runtime,
                    ctx.nodes,
                    control,
                    cast_plan,
                    ctx.masker,
                    echo=opts.echo,
                )
            )
            log_cast_run(
                repo,
                "provision",
                reports,
                ctx.masker,
            )
        return reports

    def _cast_batch(
        self,
        runner: CastRunner,
        inventory: Path,
        live: list[str],
        plan: CastPlan,
        masker: ValueMasker,
        echo: Callable[[str], None] | None,
    ) -> dict[str, CastReport]:
        tail: deque[str] = deque(maxlen=LOG_TAIL)

        def on_stderr(line: str) -> None:
            masked = masker.mask(line)
            tail.append(masked)
            if echo is not None:
                echo(masked)

        remaining = list(live)
        failed: dict[str, str] = {}
        changed: dict[str, list[str]] = {node_id: [] for node_id in live}
        for stage in plan.stages:
            groups: dict[tuple[str, ...], list[str]] = {}
            for node_id in remaining:
                groups.setdefault(stage[node_id], []).append(node_id)
            for runes, members in groups.items():
                try:
                    result = runner.run_streaming(
                        inventory,
                        members,
                        list(runes),
                        dry=plan.dry,
                        on_stderr=on_stderr,
                    )
                except ExternalToolError as e:
                    reason = _cast_error(
                        members,
                        e,
                        masker,
                    )
                    failed.update({node_id: reason for node_id in members})
                    continue
                stage_failed = set(result.failed_hosts) & set(members)
                if result.rc != 0 and not stage_failed:
                    stage_failed = set(members)
                for node_id in members:
                    changed[node_id].extend(masker.mask(name) for name in result.changed.get(node_id, []))
                failed.update({node_id: f"cast failed (exit {result.rc})" for node_id in stage_failed})
            remaining = [node_id for node_id in remaining if node_id not in failed]

        reports: dict[str, CastReport] = {}
        for node_id in live:
            names = list(dict.fromkeys(changed[node_id]))
            if node_id in failed:
                reports[node_id] = CastReport(
                    Outcome(Status.FAILED, failed[node_id]),
                    names,
                    list(tail),
                )
            elif names:
                reports[node_id] = CastReport(Outcome(Status.OK, "would change" if plan.dry else None), names)
            else:
                reports[node_id] = CastReport(Outcome(Status.UNCHANGED))
        return reports
