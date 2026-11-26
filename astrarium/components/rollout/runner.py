"""Per-node apply: stage, upload, launch detached payload, reconcile, classify."""

from __future__ import annotations

import logging
import re
import shlex
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path

from astrarium.components.rollout import transport as _transport
from astrarium.components.rollout.artifacts import XrayArtifact, head_commit, sha256_file
from astrarium.components.rollout.outcomes import PAYLOAD_RESULTS, UNKNOWN_STATE, Outcome, Status
from astrarium.components.rollout.plan import NodePlan
from astrarium.components.rollout.report import RUN_ID_PATTERN
from astrarium.components.rollout.transport import CommandResult, Transport, with_retries


LOG = logging.getLogger(__name__)

PAYLOAD_NAME = "apply.sh"

LOCK_WAIT = 30
"""Seconds launch waits for node lock before reporting `locked`."""

RECONCILE_WAIT = 600
"""Seconds reconcile waits for running apply to release lock."""

STAGE_TIMEOUT = 300.0

LAUNCH_TIMEOUT = float(LOCK_WAIT + 60)

DEFAULT_SETTLE = 3
"""Whole seconds, payload rejects fractions."""

_STAGE_PATH = re.compile(r"/[A-Za-z0-9._/-]+/\.astrarium/runs/(?P<run>[A-Za-z0-9._-]+)/stage\.[A-Za-z0-9]+")

_MISSING_SCRIPT = 127

STAGING_FAILED = Outcome(Status.FAILED, "staging")

UPLOAD_FAILED = Outcome(Status.FAILED, "upload")

LAUNCH_FAILED = Outcome(Status.FAILED, "launch failed")


def payload_file() -> AbstractContextManager[Path]:
    return as_file(files("astrarium.payloads") / PAYLOAD_NAME)


def _run_dir(run_id: str) -> str:
    return f'"$HOME/.astrarium/runs/{run_id}"'


async def _retrying(call: Callable[[], Awaitable[CommandResult]]) -> CommandResult:
    return await with_retries(call, base_delay=_transport.RETRY_DELAY)


async def _remove_stage(transport: Transport, node: str, stage: str) -> None:
    await transport.run(
        node,
        f"rm -rf -- {shlex.quote(stage)}",
        timeout=STAGE_TIMEOUT,
    )


@dataclass(frozen=True)
class ApplyParams:
    run_id: str
    commit: str
    settle: int
    force: bool
    deploy_user: str


def xray_expect(binary: XrayArtifact | None) -> str:
    """Payload XRAY_EXPECT: build:<sha> for main@sha, version:<x.y.z> for release tags, - without binary."""

    if binary is None:
        return "-"
    commit = head_commit(binary.label) if binary.label.startswith("main@") else None
    return f"build:{commit}" if commit else f"version:{binary.label.removeprefix('v')}"


def payload_args(plan: NodePlan, params: ApplyParams) -> list[str]:
    """KEY=VALUE arguments shared by launch and reconcile."""

    def new_sha(path: Path | None) -> str:
        return sha256_file(path) if path is not None else "-"

    return [
        f"RUN={params.run_id}",
        f"COMMIT={params.commit}",
        f"EXPECT_COMMIT={plan.before.recorded_commit or '-'}",
        f"FORCE={int(params.force)}",
        f"SETTLE={params.settle}",
        f"LOCK_WAIT={LOCK_WAIT}",
        f"CONFIG_BEFORE={plan.before.config_sha or '-'}",
        f"HAPROXY_BEFORE={plan.before.haproxy_sha or '-'}",
        f"XRAY_BEFORE={plan.before.xray_sha or '-'}",
        f"CONFIG_NEW={new_sha(plan.config)}",
        f"HAPROXY_NEW={new_sha(plan.haproxy)}",
        f"XRAY_NEW={plan.binary.sha256 if plan.binary else '-'}",
        f"HAPROXY_INSTALLED={int(plan.haproxy_installed)}",
        f"XRAY_EXPECT={xray_expect(plan.binary)}",
    ]


def parse_verdict(stdout: str) -> str | None:
    """Last `result=` value printed by payload."""

    results = [line.removeprefix("result=").strip() for line in stdout.splitlines() if line.startswith("result=")]
    return results[-1] if results else None


async def _attempt(transport: Transport, plan: NodePlan, params: ApplyParams) -> Outcome | str:
    node, run = plan.node_id, params.run_id
    stage_cmd = f"umask 077 && mkdir -p {_run_dir(run)} && mktemp -d {_run_dir(run)}/stage.XXXXXXXX"
    staged = await _retrying(lambda: transport.run(node, stage_cmd, timeout=STAGE_TIMEOUT))
    lines = staged.stdout.strip().splitlines()
    stage = lines[-1] if staged.rc == 0 and lines else ""
    match = _STAGE_PATH.fullmatch(stage)
    if match is None or match["run"] != run:
        LOG.warning(
            f"{node}: stage failed (rc {staged.rc}, stdout {staged.stdout.strip()!r}): {staged.stderr.strip()}",
        )
        return STAGING_FAILED
    with payload_file() as script:
        uploads = {PAYLOAD_NAME: script}
        if plan.config is not None:
            uploads["config.json"] = plan.config
        if plan.haproxy is not None:
            uploads["haproxy.cfg"] = plan.haproxy
        if plan.binary is not None:
            uploads["xray"] = plan.binary.binary
        uploaded = await _retrying(lambda: transport.upload(node, uploads, stage))
    if uploaded.rc != 0:
        LOG.warning(
            f"{node}: upload failed (rc {uploaded.rc}): {uploaded.stderr.strip()}",
        )
        await _remove_stage(
            transport,
            node,
            stage,
        )
        return UPLOAD_FAILED
    args = " ".join(shlex.quote(arg) for arg in payload_args(plan, params))
    launch = f"bash {shlex.quote(f'{stage}/{PAYLOAD_NAME}')} launch {args} {shlex.quote(f'STAGE={stage}')}"
    launched = await transport.run(
        node,
        launch,
        timeout=LAUNCH_TIMEOUT,
    )
    if launched.rc not in (0, _transport.TRANSPORT_FAILURE):
        LOG.warning(
            f"{node}: launch failed (rc {launched.rc}): {launched.stderr.strip()}",
        )
        await _remove_stage(
            transport,
            node,
            stage,
        )
        return LAUNCH_FAILED
    if launched.rc == 0 and parse_verdict(launched.stdout) == "locked":
        await _remove_stage(
            transport,
            node,
            stage,
        )
        return PAYLOAD_RESULTS["locked"]
    reconcile = f"bash {_run_dir(run)}/{PAYLOAD_NAME} reconcile {args} WAIT={RECONCILE_WAIT}"
    result = await _retrying(lambda: transport.run(node, reconcile, timeout=RECONCILE_WAIT + 60))
    if result.rc == _MISSING_SCRIPT:
        return "pending"
    verdict = parse_verdict(result.stdout) if result.rc == 0 else None
    if verdict == "pending":
        return verdict
    outcome = PAYLOAD_RESULTS.get(verdict) if verdict is not None else None
    if outcome is None:
        LOG.warning(
            f"{node}: reconcile exited {result.rc}, result {verdict!r}: {result.stderr.strip()}",
        )
        return UNKNOWN_STATE
    return outcome


async def apply_node(transport: Transport, plan: NodePlan, params: ApplyParams) -> Outcome:
    """Stage, upload, launch, reconcile, relaunch once more only when payload recorded no swap."""

    if RUN_ID_PATTERN.fullmatch(params.run_id) is None:
        raise ValueError(f"invalid run id {params.run_id!r}")
    for attempt in (1, 2):
        result = await _attempt(
            transport,
            plan,
            params,
        )
        if isinstance(result, Outcome):
            return result
        LOG.info(
            f"{plan.node_id}: payload did not swap (attempt {attempt})",
        )
    return UNKNOWN_STATE


async def apply_log_tail(transport: Transport, node_id: str, run_id: str, lines: int = 40) -> str:
    """Tail of node-side payload log, for local run log."""

    result = await transport.run(
        node_id,
        f"tail -n {lines} {_run_dir(run_id)}/apply.log",
        timeout=STAGE_TIMEOUT,
    )
    return result.stdout if result.rc == 0 else ""


async def verify_node(transport: Transport, node_id: str, *, haproxy: bool) -> bool:
    """Canary re-check: xray (and wanted HAProxy) still active."""

    command = "systemctl is-active --quiet xray"
    if haproxy:
        command += " && systemctl is-active --quiet haproxy"
    result = await _retrying(lambda: transport.run(node_id, command, timeout=STAGE_TIMEOUT))
    return result.rc == 0
