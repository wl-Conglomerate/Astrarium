"""Run summaries to Discord (summary only)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from astrarium.components.manifest.models import DiscordNotify
from astrarium.components.notify.discord import send_summary
from astrarium.components.rollout.outcomes import Outcome, Status, run_exit_code
from astrarium.components.rollout.report import summary_counts
from astrarium.core import BaseController
from astrarium.errors import ExitCode


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


def _ci_fields() -> dict[str, str]:
    """Trigger and run link in GitHub Actions, `local` elsewhere."""

    if os.environ.get("GITHUB_ACTIONS") != "true":
        return {"Trigger": "local"}
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    actor = os.environ.get("GITHUB_ACTOR", "")
    url = "{}/{}/actions/runs/{}".format(
        os.environ.get("GITHUB_SERVER_URL", "https://github.com"),
        os.environ.get("GITHUB_REPOSITORY", ""),
        os.environ.get("GITHUB_RUN_ID", ""),
    )
    return {"Trigger": f"{event} ({actor})", "Run": f"[logs]({url})"}


class NotifyController(BaseController["AstrariumApp"]):
    """Run summaries to configured channels (Discord only)."""

    def deploy_summary(
        self,
        discord: DiscordNotify,
        *,
        title: str,
        outcomes: Mapping[str, Outcome],
        scope: str,
        commit: str,
        run_id: str,
        extra: Mapping[str, str],
        summary_file: Path,
        client: httpx.Client | None = None,
    ) -> int:
        """Send counts, failed nodes and node/outcome text file, never diffs or config content."""

        if not discord.webhook_url:
            return 0
        counts = summary_counts(outcomes)
        failed = [f"{node_id} {outcome}" for node_id, outcome in outcomes.items() if outcome.status is Status.FAILED]
        ok = run_exit_code(outcomes) is ExitCode.OK
        fields = {
            "Scope": scope,
            "Commit": f"`{commit[:12]}`",
            "Run id": run_id,
            "Result": ", ".join(f"{count} {name}" for name, count in counts.items() if count),
            "Failed": "\n".join(failed) or "-",
            **_ci_fields(),
            **extra,
        }
        summary_file.write_text("".join(f"{node_id} {outcome}\n" for node_id, outcome in outcomes.items()))
        verdict = "succeeded" if ok else "failed"
        return send_summary(
            discord.webhook_url,
            discord.thread_id,
            title=f"{title} {verdict}",
            fields=fields,
            ok=ok,
            log=summary_file,
            client=client,
        )
