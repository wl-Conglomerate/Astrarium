"""Stripped topology for Orrery collector until NullForge feature lands."""

from __future__ import annotations

import hashlib
import logging
import shlex
from collections.abc import Mapping

import yaml

from astrarium.components.rollout.transport import Transport
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.topology.bridge import HexRiftNode


LOG = logging.getLogger(__name__)

UPLOAD_TIMEOUT = 60.0

_UPLOAD = """\
set -u
target={target}
have=$(sha256sum "$target" 2>/dev/null | cut -d' ' -f1)
if [ "$have" = {sha} ]; then echo unchanged; exit 0; fi
if tmp=$(mktemp "$(dirname "$target")/.astrarium-topology.XXXXXX" 2>/dev/null); then
    cat > "$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$target" || {{ rm -f "$tmp"; exit 1; }}
else
    cat > "$target" || exit 1
fi
echo updated
"""


def upload_script(path: str, text: str) -> str:
    return _UPLOAD.format(target=shlex.quote(path), sha=hashlib.sha256(text.encode()).hexdigest())


def stripped_topology(hexrift: Mapping[str, HexRiftNode]) -> str:
    """Subset Orrery reads: regions[].{id, type, nodes[].{id, hostname}}."""

    regions: dict[str, dict] = {}
    for node in hexrift.values():
        region = regions.setdefault(
            node.region,
            {
                "id": node.region,
                "type": node.type,
                "nodes": [],
            },
        )
        region["nodes"].append({"id": node.id, "hostname": node.hostname})
    return yaml.safe_dump({"regions": list(regions.values())}, sort_keys=False)


async def upload_topology(transport: Transport, node_id: str, path: str, text: str, masker: ValueMasker) -> str:
    """Upload result: updated, unchanged or failed, failure stderr logged masked."""

    result = await transport.run(
        node_id,
        f"bash -c {shlex.quote(upload_script(path, text))}",
        stdin=text.encode(),
        timeout=UPLOAD_TIMEOUT,
    )
    lines = result.stdout.split()
    if result.rc == 0 and lines and lines[-1] in ("updated", "unchanged"):
        return lines[-1]
    LOG.warning(
        f"{node_id}: topology upload failed (rc {result.rc}): {masker.mask(result.stderr.strip())}",
    )
    return "failed"
