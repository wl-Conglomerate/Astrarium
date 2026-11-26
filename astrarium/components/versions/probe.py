"""Read-only installed-version probes, pin matching and per-node version cells."""

from __future__ import annotations

import asyncio
import logging
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from nullforge.smithy.versions import VERSION_COMMANDS

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.models import Manifest, VersionPin, XrayRelease
from astrarium.components.rollout.artifacts import head_commit, pin_label
from astrarium.components.rollout.transport import Transport
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.versions.registry import Component, feature_enabled, pin_layer


LOG = logging.getLogger(__name__)

PROBE_MARK = "@@astrarium "

MISSING = "@@missing"

PROBE_TIMEOUT = 60.0

COMMAND_TIMEOUT = 10

VERSION_TOKEN = re.compile(r"v?\d+(?:\.\d+)+[0-9A-Za-z.+-]*")

NO_HOST_KEYS: Final = "no host keys"

CellState = Literal["match", "mismatch", "missing", "unknown", "unreachable", "not probed", "no host keys"]

MISMATCH_STATES: frozenset[str] = frozenset(
    {
        "mismatch",
        "missing",
        "unreachable",
    }
)


@dataclass(frozen=True)
class InstalledVersion:
    name: str
    present: bool
    lines: tuple[str, ...]


@dataclass(frozen=True)
class VersionCell:
    component: str
    pin: str | None
    layer: str
    installed: str
    state: CellState


def build_probe_script(components: Iterable[Component]) -> str:
    """Remote command printing marked probe output per component under POSIX sh, always exits 0."""

    lines = [f'run() {{ if command -v timeout >/dev/null 2>&1; then timeout {COMMAND_TIMEOUT} "$@"; else "$@"; fi; }}']
    for component in components:
        if component.probe is None:
            continue
        lines.append(f"printf '%s\\n' {shlex.quote(PROBE_MARK + component.name)}")
        probe = f"run sh -c {shlex.quote(component.probe)} 2>&1 | head -n 3"
        if component.binary is not None:
            lines.append(f"if [ -e {shlex.quote(component.binary)} ]; then {probe}; else echo {MISSING}; fi")
        else:
            lines.append(probe)
    lines.append("true")
    return "sh -c " + shlex.quote("\n".join(lines))


def parse_probe_output(stdout: str) -> dict[str, InstalledVersion]:
    """Probe results per component from build_probe_script output."""

    found: dict[str, list[str]] = {}
    current: str | None = None
    for line in stdout.splitlines():
        if line.startswith(PROBE_MARK):
            current = line.removeprefix(PROBE_MARK).strip()
            found[current] = []
        elif current is not None:
            found[current].append(line.strip())
    return {
        name: InstalledVersion(
            name=name,
            present=MISSING not in lines,
            lines=tuple(line[:200] for line in lines if line and line != MISSING),
        )
        for name, lines in found.items()
    }


def version_in(pin: str, text: str) -> bool:
    """Pin (optional `v` dropped) appears in text as whole version token: 3.5.1 never inside 3.5.10 or 3.5.1a."""

    core = re.escape(pin.removeprefix("v"))
    return re.search(rf"(?<![0-9A-Za-z.])v?{core}(?![0-9A-Za-z]|\.\d)", text) is not None


def pin_matches(component: Component, pin: VersionPin | None, installed: InstalledVersion | None) -> bool | None:
    """Installed equals pin: version token or marker line for NullForge tools, version field or commit for xray.

    None when unknown.
    """

    if pin is None or installed is None:
        return None
    if not installed.present:
        return False
    text = " ".join(installed.lines)
    if component.owner == "astrarium":
        fields = installed.lines[0].split() if installed.lines else []
        if isinstance(pin, XrayRelease):
            return len(fields) >= 2 and fields[1] == pin.version.removeprefix("v")
        commit = head_commit(pin)
        return commit is not None and commit in text
    if not isinstance(pin, str):
        return None
    if pin == "latest":
        return True
    if VERSION_COMMANDS.get(component.name, "") is None:
        return bool(installed.lines) and installed.lines[0] == pin
    return version_in(pin, text)


def installed_label(component: Component, installed: InstalledVersion | None) -> str:
    """Installed version as shown in tables."""

    if installed is None:
        return "?"
    if not installed.present:
        return "missing"
    if component.owner == "astrarium":
        fields = installed.lines[0].split() if installed.lines else []
        return fields[1] if len(fields) >= 2 else "?"
    match = VERSION_TOKEN.search(" ".join(installed.lines))
    if match is not None:
        return match.group(0)
    return installed.lines[0][:40] if installed.lines else "?"


async def probe_nodes(
    transport: Transport,
    node_ids: Sequence[str],
    components: Mapping[str, Sequence[Component]],
    masker: ValueMasker,
) -> tuple[dict[str, dict[str, InstalledVersion] | None], dict[str, int]]:
    """One probe command per node. None (cell stays fail-closed) for node whose probe command failed,
    node's rc in second dict for caller reporting it (versions apply's re-probe)."""

    failed: dict[str, int] = {}

    async def one(node_id: str) -> tuple[str, dict[str, InstalledVersion] | None]:
        wanted = [component for component in components.get(node_id, []) if component.probe is not None]
        if not wanted:
            return node_id, {}
        result = await transport.run(
            node_id,
            build_probe_script(wanted),
            timeout=PROBE_TIMEOUT,
        )
        if result.rc != 0:
            LOG.warning(
                f"{node_id}: version probe failed (rc {result.rc}): {masker.mask(result.stderr.strip())}",
            )
            failed[node_id] = result.rc
            return node_id, None
        return node_id, parse_probe_output(masker.mask(result.stdout))

    probes = dict(await asyncio.gather(*(one(node_id) for node_id in node_ids)))
    return probes, failed


def node_cells(
    node: EffectiveNode,
    manifest: Manifest,
    registry: Mapping[str, Component],
    names: Sequence[str],
    probes: Mapping[str, InstalledVersion] | None,
    *,
    probed: bool,
) -> list[VersionCell]:
    """Cells of components enabled on node, installed compared with node's effective pin.

    Node without host_keys is never probed: its cells read `no host keys`.
    """

    cells: list[VersionCell] = []
    for name in names:
        component = registry[name]
        if component.owner == "tooling" or not feature_enabled(node.features, component.feature):
            continue
        pin, layer = pin_layer(
            manifest,
            name,
            node.id,
        )
        label = pin_label(pin) if pin is not None else None
        if not node.host_keys:
            cells.append(
                VersionCell(
                    name,
                    label,
                    layer,
                    "-",
                    NO_HOST_KEYS,
                )
            )
            continue
        if not probed:
            cells.append(
                VersionCell(
                    name,
                    label,
                    layer,
                    "-",
                    "not probed",
                )
            )
            continue
        if probes is None:
            cells.append(
                VersionCell(
                    name,
                    label,
                    layer,
                    "?",
                    "unreachable",
                )
            )
            continue
        installed = probes.get(name)
        match = pin_matches(
            component,
            pin,
            installed,
        )
        state: CellState
        if installed is not None and not installed.present:
            state = "missing"
        elif match is None:
            state = "unknown"
        else:
            state = "match" if match else "mismatch"
        cells.append(
            VersionCell(
                name,
                label,
                layer,
                installed_label(component, installed),
                state,
            )
        )
    return cells
