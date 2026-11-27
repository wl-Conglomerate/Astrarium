"""SSH routes for cast runs: deploy lock check, fresh-login checks after SSH-sensitive batches."""

from __future__ import annotations

import asyncio
import logging
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import ControlSection, Identity
from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.rollout.transport import TRANSPORT_FAILURE, Transport, write_scoped_ssh
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.sshcfg.render import SshPaths, Via
from astrarium.errors import Refused, UsageProblem
from astrarium.runtime import RuntimeDir


LOG = logging.getLogger(__name__)

CastIdentity = Literal["admin", "ci", "root"]

PATH_PROBE = "echo astrarium-path-ok"

PROBE_TIMEOUT = 30.0

LOCK_CHECK_TIMEOUT = 30.0

LOCK_BUSY_RC = 75

NO_BASTION_LOGIN: frozenset[str] = frozenset({"deploy", "ci", "root"})
"""Identities without shell on bastions: jump-only deploy account, no CI cast user, root never used there."""


def check_cast_identity(identity: CastIdentity, via: Via, control: ControlSection) -> None:
    """CI casts need control.ci.cast_keys and jump route, cast keys carry from=<jump>."""

    if identity != "ci":
        return
    if control.ci is None or not control.ci.cast_keys:
        raise UsageProblem("--as ci needs control.ci.cast_keys in astrarium.yaml")
    if via != "jump":
        raise Refused(
            "--as ci works only through the jump host", hint="CI cast keys are restricted to the jump addresses"
        )


def paths_in_use(identity: CastIdentity, via: Via, control: ControlSection) -> list[tuple[Identity, Via]]:
    """Identities and routes checked after SSH-sensitive batches: deploy and cast identity, cast route and jump.

    Root is intentionally killed by the cast's users/netsec runes, so a root cast re-probes deploy only.
    """

    routes: list[Via] = [via]
    if control.jump is not None and via != "jump":
        routes.append("jump")
    identities: list[Identity] = ["deploy"] if identity == "root" else ["deploy", identity]
    return [(who, route) for who in identities for route in routes]


def probe_targets(
    nodes: Mapping[str, EffectiveNode],
    paths: SshPaths,
    identity: Identity,
    batch: Sequence[str],
    *,
    jump_batch: bool,
) -> list[str]:
    """Fresh-login targets, never outside paths.nodes: whole scope after jump batch, else batch.

    No bastion shell for hop accounts (NO_BASTION_LOGIN).
    """

    pool = sorted(paths.nodes) if jump_batch else [node_id for node_id in batch if node_id in paths.nodes]
    if identity in NO_BASTION_LOGIN:
        pool = [node_id for node_id in pool if nodes[node_id].root_role != "bastion"]
    return pool


def hop_targets(
    nodes: Mapping[str, EffectiveNode],
    paths: SshPaths,
    identity: Identity,
    batch: Sequence[str],
    *,
    jump_batch: bool,
) -> list[str]:
    """Bastion of jump batch for hop identities (NO_BASTION_LOGIN), checked auth only, within paths.nodes.

    Hop login runs forced nologin (exit 1), so only TRANSPORT_FAILURE counts as failure there.
    """

    if not jump_batch or identity not in NO_BASTION_LOGIN:
        return []
    return [node_id for node_id in batch if node_id in paths.nodes and nodes[node_id].root_role == "bastion"]


@dataclass(frozen=True)
class PathFailure:
    node_id: str
    identity: Identity
    via: Via
    rc: int


def run_scoped_transports(
    runtime: RuntimeDir,
    nodes: Mapping[str, EffectiveNode],
    control: ControlSection,
    make_transport: Callable[[SshPaths, frozenset[str]], Transport],
    wanted: Iterable[str],
) -> Callable[[Identity, Via], tuple[SshPaths, Transport]]:
    """Opener for verify_paths: one write_scoped_ssh call and one transport per (identity, via) pair,
    built when that pair is first opened, reused for every later batch.

    `wanted` is whole run's target list, not one batch: `ssh -F` re-reads shared per-route
    files on every call (write_ssh_files always writes same `ssh-<identity>-<via>` path), so
    rebuilding per batch would silently drop still-live Host entries of earlier batches.
    """

    wanted = list(wanted)
    opened: dict[tuple[Identity, Via], tuple[SshPaths, Transport]] = {}

    def open_transport(identity: Identity, via: Via) -> tuple[SshPaths, Transport]:
        key = (identity, via)
        if key not in opened:
            paths, jumped = write_scoped_ssh(
                runtime,
                nodes,
                control,
                identity,
                via,
                wanted=wanted,
            )
            opened[key] = (paths, make_transport(paths, jumped))
        return opened[key]

    return open_transport


async def verify_paths(
    open_transport: Callable[[Identity, Via], tuple[SshPaths, Transport]],
    nodes: Mapping[str, EffectiveNode],
    pairs: Sequence[tuple[Identity, Via]],
    batch: Sequence[str],
    *,
    jump_batch: bool,
) -> list[PathFailure]:
    """Fresh login per identity/route pair: PATH_PROBE against probe_targets (exit 0 wanted) and
    hop_targets (auth only), over run-scoped paths caller already opened (see run_scoped_transports).
    Pairs probe concurrently, each over its own ssh-<identity>-<via> files.
    """

    async def one_pair(identity: Identity, via: Via) -> list[PathFailure]:
        paths, transport = open_transport(identity, via)
        hops = hop_targets(
            nodes,
            paths,
            identity,
            batch,
            jump_batch=jump_batch,
        )
        targets = [
            *probe_targets(
                nodes,
                paths,
                identity,
                batch,
                jump_batch=jump_batch,
            ),
            *hops,
        ]
        if not targets:
            return []
        results = await asyncio.gather(
            *(
                transport.run(
                    node_id,
                    PATH_PROBE,
                    timeout=PROBE_TIMEOUT,
                )
                for node_id in targets
            )
        )
        return [
            PathFailure(
                node_id=node_id,
                identity=identity,
                via=via,
                rc=result.rc,
            )
            for node_id, result in zip(
                targets,
                results,
                strict=True,
            )
            if (result.rc == TRANSPORT_FAILURE if node_id in hops else result.rc != 0)
        ]

    gathered = await asyncio.gather(*(one_pair(identity, via) for identity, via in pairs))
    return [failure for pair_failures in gathered for failure in pair_failures]


def lock_check_command(deploy_user: str) -> str:
    """Remote command exiting LOCK_BUSY_RC while deploy holds `~<deploy_user>/.astrarium/lock`, else 0.

    Checks `sudo -n` before existence test: refusal (password required, no sudoers
    entry) exits nonzero (never 0, never LOCK_BUSY_RC), so it fails closed instead of reading as
    lock absent.
    """

    user = shlex.quote(deploy_user)
    script = (
        f"home=$(getent passwd {user} | cut -d: -f6); "
        'if [ -z "$home" ]; then exit 0; fi; '
        "sudo -n true || exit 1; "
        'lock="$home/.astrarium/lock"; '
        'if ! sudo -n test -e "$lock"; then exit 0; fi; '
        f'sudo -n flock -n -E {LOCK_BUSY_RC} "$lock" true'
    )
    return "sh -c " + shlex.quote(script)


async def deploy_busy(
    transport: Transport,
    node_ids: Sequence[str],
    deploy_user: str,
    masker: ValueMasker,
) -> dict[str, Outcome]:
    """Nodes to leave out of next batch: deploy holds lock, or check itself failed (fail-closed)."""

    command = lock_check_command(deploy_user)
    results = await asyncio.gather(
        *(
            transport.run(
                node_id,
                command,
                timeout=LOCK_CHECK_TIMEOUT,
            )
            for node_id in node_ids
        )
    )
    blocked: dict[str, Outcome] = {}
    for node_id, result in zip(
        node_ids,
        results,
        strict=True,
    ):
        if result.rc == 0:
            continue
        if result.rc == LOCK_BUSY_RC:
            blocked[node_id] = Outcome(Status.NOT_ATTEMPTED, "deploy in progress")
            continue
        LOG.warning(
            f"{node_id}: deploy lock check failed (rc {result.rc}): {masker.mask(result.stderr.strip())}",
        )
        reason = "unreachable" if result.rc == TRANSPORT_FAILURE else f"deploy lock check failed (exit {result.rc})"
        blocked[node_id] = Outcome(Status.FAILED, reason)
    return blocked
