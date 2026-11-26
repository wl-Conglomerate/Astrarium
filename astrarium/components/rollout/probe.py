"""Read-only probe of live xray/HAProxy files, xray version and recorded commit."""

from __future__ import annotations

import logging
import re
import shlex
from dataclasses import dataclass

from astrarium.components.rollout import transport as _transport
from astrarium.components.rollout.outcomes import UNREACHABLE, Outcome, Status
from astrarium.components.rollout.transport import Transport, with_retries


LOG = logging.getLogger(__name__)

XRAY_CONFIG = "/usr/local/etc/xray/config.json"

HAPROXY_CONFIG = "/etc/haproxy/haproxy.cfg"

XRAY_BINARY = "/usr/local/bin/xray"

PROBE_MARKER = "@@astrarium-probe"

PROBE_TIMEOUT = 60.0

PROBE_COMMAND = f"""\
h() {{ if s=$(sha256sum "$1" 2>/dev/null); then echo "${{s%% *}}"; else echo -; fi; }}
echo {PROBE_MARKER}
echo "config $(h {XRAY_CONFIG})"
echo "haproxy $(h {HAPROXY_CONFIG})"
echo "xray $(h {XRAY_BINARY})"
v=$({XRAY_BINARY} version 2>/dev/null | head -n 1)
echo "version ${{v:--}}"
echo "arch $(uname -m)"
c=$(sed -n 's/^commit=//p' "$HOME/.astrarium/state" 2>/dev/null | tail -n 1)
echo "commit ${{c:--}}"
"""
"""Script fed to `bash -s` as deploy user, one `key value` line per fact after marker."""

_VERSION_LINE = re.compile(r"Xray (\S+) \(.*?\) (\S+) \(")


@dataclass(frozen=True)
class LiveState:
    config_sha: str | None
    haproxy_sha: str | None
    xray_sha: str | None
    xray_build: str | None
    recorded_commit: str | None
    arch: str | None


def parse_probe(stdout: str) -> LiveState:
    """Facts after last marker line, earlier output ignored, ValueError without marker."""

    lines = stdout.splitlines()
    if PROBE_MARKER not in lines:
        raise ValueError("probe output has no marker")
    start = len(lines) - lines[::-1].index(PROBE_MARKER)
    facts = dict(line.partition(" ")[::2] for line in lines[start:])

    def fact(key: str) -> str | None:
        value = facts.get(key, "-").strip()
        return None if value in ("", "-") else value

    build = None
    if (line := fact("version")) and (match := _VERSION_LINE.match(line)):
        build = match.group(2)
    return LiveState(
        config_sha=fact("config"),
        haproxy_sha=fact("haproxy"),
        xray_sha=fact("xray"),
        xray_build=build,
        recorded_commit=fact("commit"),
        arch=fact("arch"),
    )


async def probe(transport: Transport, node_id: str) -> LiveState | Outcome:
    """Live state, UNREACHABLE after transport retries, FAILED for other exits or unreadable output."""

    result = await with_retries(
        lambda: transport.run(node_id, "bash -s", stdin=PROBE_COMMAND.encode(), timeout=PROBE_TIMEOUT),
        base_delay=_transport.RETRY_DELAY,
    )
    if result.rc == _transport.TRANSPORT_FAILURE:
        return UNREACHABLE
    if result.rc != 0:
        LOG.warning(
            f"probe on {node_id} exited {result.rc}: {result.stderr.strip()}",
        )
        return Outcome(Status.FAILED, f"probe exit {result.rc}")
    try:
        return parse_probe(result.stdout)
    except ValueError as e:
        LOG.warning(
            f"probe output on {node_id} unreadable: {e}",
        )
        return Outcome(Status.FAILED, "probe output unreadable")


async def reachable(transport: Transport, node_id: str) -> bool:
    """SSH login works, any exit but 255 so forced-command jump-only account counts as reachable."""

    result = await with_retries(
        lambda: transport.run(node_id, "true", timeout=PROBE_TIMEOUT), base_delay=_transport.RETRY_DELAY
    )
    return result.rc != _transport.TRANSPORT_FAILURE


async def fetch_file(transport: Transport, node_id: str, path: str) -> str | None:
    """Text of remote file for diffs, None when missing or unreadable."""

    result = await with_retries(
        lambda: transport.run(node_id, f"cat -- {shlex.quote(path)}", timeout=PROBE_TIMEOUT),
        base_delay=_transport.RETRY_DELAY,
    )
    return result.stdout if result.rc == 0 else None
