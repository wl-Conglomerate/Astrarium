"""NullForge casts as subprocess: argv, limit safety, pyinfra --json parsing, SSH-sensitive changes."""

from __future__ import annotations

import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from astrarium.components.manifest.models import BUILTIN_ROLES, NODE_ID_PATTERN
from astrarium.components.sshcfg.render import JUMP_CONCURRENCY
from astrarium.errors import ExternalToolError, InvalidManifest, Refused


LOG = logging.getLogger(__name__)

RESERVED_LIMITS = frozenset({"all", *BUILTIN_ROLES})
"""pyinfra resolves --limit as group name before host name (pyinfra_cli/cli.py:762-780)."""

SSH_SENSITIVE_RUNES = frozenset(
    {
        "netsec",
        "users",
        "deploy_access",
        "ci_access",
    }
)
"""Runes whose changes can cut SSH logins: sshd and UFW, admin keys, deploy and CI accounts."""

_SIGINT_GRACE = 10.0
"""Seconds to let NullForge's own subprocess.run kill its pyinfra child after SIGINT, before SIGKILL."""

_NODE_ID = re.compile(NODE_ID_PATTERN)

CAST_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TERM",
        "TMPDIR",
        "SSH_AUTH_SOCK",
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "PYTHONHOME",
        "NO_COLOR",
        "FORCE_COLOR",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "https_proxy",
        "http_proxy",
        "no_proxy",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
    }
)
"""Environment names NullForge cast inherits (plus LC_*); no sops or index credentials."""


def touches_ssh(changed: Mapping[str, list[str]], node_ids: Iterable[str]) -> bool:
    return any(rune_of(name) in SSH_SENSITIVE_RUNES for node_id in node_ids for name in changed.get(node_id, []))


def cast_env(environ: Mapping[str, str]) -> dict[str, str]:
    return {name: value for name, value in environ.items() if name in CAST_ENV or name.startswith("LC_")}


@dataclass(frozen=True)
class CastResult:
    rc: int
    failed_hosts: list[str]
    changed: dict[str, list[str]]
    stages: int


def check_limits(limits: Iterable[str]) -> list[str]:
    """Limits safe to pass as one --limit each: non-empty, plain node ids, never pyinfra group names."""

    checked = list(limits)
    if not checked:
        raise Refused("cast without --limit would target every inventory host")
    for node_id in checked:
        if not _NODE_ID.fullmatch(node_id):
            raise InvalidManifest(
                f"node id {node_id!r} is not a plain id", hint="fnmatch characters widen pyinfra --limit"
            )
        if node_id in RESERVED_LIMITS:
            raise InvalidManifest(f"node id {node_id!r} collides with a pyinfra group name", hint="rename the node")
    return checked


def rune_of(op_name: str) -> str | None:
    """Rune stem labelling op name `<rune> | <op>` (pyinfra/api/operation.py:407-408), None when unlabelled."""

    label, separator, _ = op_name.partition(" | ")
    if not separator:
        return None
    return label.rsplit("/", 1)[-1].removesuffix(".py")


def _add(changed: dict[str, list[str]], hosts: Iterable[str], names: Iterable[str]) -> None:
    wanted = list(names)
    for host in hosts:
        bucket = changed.setdefault(host, [])
        bucket.extend(name for name in wanted if name not in bucket)


def _merge(document: dict[str, Any], failed: set[str], changed: dict[str, list[str]]) -> None:
    results = document.get("results")
    if results is None:
        for op in document.get("plan", []):
            hosts = [*op.get("hosts_with_change", []), *op.get("hosts_with_conditional_change", [])]
            _add(
                changed,
                hosts,
                op.get("names", []),
            )
        return
    failed.update(results.get("failed_hosts", []))
    for op in results.get("operations", []):
        _add(
            changed,
            op.get("success", []),
            op.get("names", []),
        )


def parse_cast_output(stdout: str) -> tuple[list[str], dict[str, list[str]], int]:
    """(failed hosts, host -> changed op names, stage count) from pyinfra --json stdout, op args never kept."""

    decoder = json.JSONDecoder()
    failed: set[str] = set()
    changed: dict[str, list[str]] = {}
    stages = 0
    position = 0
    while True:
        while position < len(stdout) and stdout[position].isspace():
            position += 1
        if position >= len(stdout):
            break
        try:
            document, position = decoder.raw_decode(stdout, position)
        except json.JSONDecodeError as e:
            LOG.warning(f"cast stdout is not valid JSON, hiding content: {e}")
            raise ExternalToolError(
                "NullForge cast printed non-JSON output on stdout",
                hint="stdout is not shown because it may hold secrets",
            ) from None
        if not isinstance(document, dict) or "plan" not in document:
            raise ExternalToolError("NullForge cast printed an unexpected JSON document")
        stages += 1
        try:
            _merge(
                document,
                failed,
                changed,
            )
        except (AttributeError, TypeError) as e:
            LOG.warning(
                f"cast JSON document has unexpected shape: {type(e).__name__}: {e}",
            )
            raise ExternalToolError("NullForge cast printed an unexpected JSON document") from None
    return (
        sorted(failed),
        changed,
        stages,
    )


class CastRunner:
    """Runs `python -m nullforge.cli cast` as subprocess (pyinfra_cli patches gevent process-wide)."""

    def run(self, inventory: Path, limits: list[str], runes: list[str], *, dry: bool) -> CastResult:
        return self.run_streaming(
            inventory,
            limits,
            runes,
            dry=dry,
            on_stderr=lambda _line: None,
        )

    def __init__(self, python: str = sys.executable) -> None:
        self.python = python

    def argv(self, inventory: Path, limits: list[str], runes: list[str], *, dry: bool) -> list[str]:
        """One --limit per node, runes in order, -y, --parallel JUMP_CONCURRENCY, --json (dry adds --dry --diff)."""

        args = [
            self.python,
            "-m",
            "nullforge.cli",
            "cast",
            "-i",
            str(inventory),
        ]
        for node_id in check_limits(limits):
            args += ["--limit", node_id]
        for rune in runes:
            args += ["-r", rune]
        args += [
            "-y",
            "--parallel",
            str(JUMP_CONCURRENCY),
        ]
        if dry:
            args += ["--dry", "--diff"]
        args.append("--json")
        return args

    def run_streaming(
        self,
        inventory: Path,
        limits: list[str],
        runes: list[str],
        *,
        dry: bool,
        on_stderr: Callable[[str], None],
    ) -> CastResult:
        """Cast with inventory dir as cwd (pyinfra reads config.py, group_data/ from cwd) and cast_env.

        stdout parsed, never kept.
        """

        args = self.argv(
            inventory,
            limits,
            runes,
            dry=dry,
        )
        try:
            process = subprocess.Popen(  # noqa: S603
                args,
                cwd=inventory.parent,
                env=cast_env(os.environ),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as e:
            raise ExternalToolError(f"cannot start NullForge: {e.strerror}") from None
        stdout, stderr = process.stdout, process.stderr
        if stdout is None or stderr is None:
            process.kill()
            raise ExternalToolError("NullForge cast pipes are not available")
        chunks: list[str] = []
        reader = threading.Thread(target=lambda: chunks.append(stdout.read()), daemon=True)
        reader.start()
        try:
            for line in stderr:
                on_stderr(line.rstrip("\n"))
            rc = process.wait()
        except BaseException:
            # SIGINT (not SIGKILL) so NullForge's own subprocess.run(pyinfra_argv) sees
            # KeyboardInterrupt and kills its pyinfra child itself, SIGKILL here would orphan it.
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=_SIGINT_GRACE)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            raise
        reader.join()
        failed, changed, stages = parse_cast_output("".join(chunks))
        return CastResult(
            rc=rc,
            failed_hosts=failed,
            changed=changed,
            stages=stages,
        )
