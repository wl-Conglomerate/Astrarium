"""Run ids, outcome table and JSON, masked run log."""

from __future__ import annotations

import os
import re
import secrets
from collections import Counter
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from rich.table import Table
from rich.text import Text

from astrarium.components.rollout.outcomes import Outcome, Status
from astrarium.components.secrets.masking import ValueMasker
from astrarium.repo import Repo


RUN_ID_PATTERN = re.compile(r"[A-Za-z0-9._-]+")
"""Run ids name remote dirs and local log files."""

_STYLES = {
    Status.OK: "green",
    Status.UNCHANGED: "dim",
    Status.SKIPPED: "yellow",
    Status.FAILED: "bold red",
    Status.NOT_ATTEMPTED: "magenta",
}


def new_run_id(now: datetime | None = None) -> str:
    return f"{(now or datetime.now(UTC)):%Y%m%dT%H%M%SZ}-{secrets.token_hex(3)}"


def outcomes_json(outcomes: Mapping[str, Outcome]) -> list[dict]:
    return [
        {
            "node": node_id,
            "status": outcomes[node_id].status.value,
            "reason": outcomes[node_id].reason,
        }
        for node_id in sorted(outcomes)
    ]


def render_table(outcomes: Mapping[str, Outcome]) -> Table:
    """One row per node sorted by node id, outcome styled by status."""

    table = Table(title="Results")
    table.add_column("node")
    table.add_column("outcome")
    for node_id in sorted(outcomes):
        outcome = outcomes[node_id]
        table.add_row(Text(node_id), Text(str(outcome), style=_STYLES[outcome.status]))
    return table


def summary_counts(outcomes: Mapping[str, Outcome]) -> dict[str, int]:
    """Count per status value, every status present."""

    counts = Counter(o.status for o in outcomes.values())
    return {status.value: counts.get(status, 0) for status in Status}


class RunLog:
    """Append-only masked log at .astrarium/runs/<run_id>.log, mode 0600."""

    def __init__(self, repo: Repo, run_id: str, masker: ValueMasker) -> None:
        if RUN_ID_PATTERN.fullmatch(run_id) is None:
            raise ValueError(f"invalid run id {run_id!r}")
        repo.runs_dir.mkdir(
            parents=True,
            exist_ok=True,
            mode=0o700,
        )
        self.path: Path = repo.runs_dir / f"{run_id}.log"
        self._masker = masker
        os.close(
            os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
        )
        self.path.chmod(0o600)

    def write(self, line: str) -> None:
        """Append masked line, no trailing newline needed."""

        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(self._masker.mask(line.rstrip("\n")) + "\n")
