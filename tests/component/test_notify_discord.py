"""Discord summary: thread, embed fields, network errors, outcomes only."""

import json
import logging
from typing import Any, cast

import httpx
import pytest

from astrarium.components.manifest.models import DiscordNotify
from astrarium.components.notify import discord
from astrarium.components.notify.controller import NotifyController
from astrarium.components.rollout.outcomes import Outcome, Status


pytestmark = pytest.mark.component

HOOK = "https://discord.example.net/api/webhooks/1/token"


@pytest.fixture
def captured() -> tuple[list[httpx.Request], httpx.Client]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(204)

    return requests, httpx.Client(transport=httpx.MockTransport(handler))


def broken_client(message: str) -> httpx.Client:
    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(message)

    return httpx.Client(transport=httpx.MockTransport(broken))


def test_summary_posts_to_thread_with_embed(captured) -> None:
    requests, client = captured
    status = discord.send_summary(
        HOOK,
        "42",
        title="Deploy",
        fields={"Scope": "all"},
        ok=True,
        log=None,
        client=client,
    )

    body = json.loads(requests[0].content)
    assert status == 204
    assert requests[0].url.params["thread_id"] == "42"
    assert body["embeds"][0]["fields"][0] == {
        "name": "Scope",
        "value": "all",
        "inline": True,
    }


def test_network_error_does_not_raise() -> None:
    assert (
        discord.send_summary(
            HOOK,
            None,
            title="Deploy",
            fields={},
            ok=False,
            log=None,
            client=broken_client("down"),
        )
        == 0
    )


def test_malformed_webhook_url_does_not_raise() -> None:
    bad_hook = "https://discord.example.net:not-a-port/api/webhooks/1/token"

    status = discord.send_summary(
        bad_hook,
        None,
        title="Deploy",
        fields={},
        ok=False,
        log=None,
    )

    assert status == 0


def test_connect_error_message_omits_webhook_token(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        discord.send_summary(
            HOOK,
            None,
            title="Deploy",
            fields={},
            ok=False,
            log=None,
            client=broken_client(f"failed to reach {HOOK}"),
        )

    token = HOOK.rsplit("/", 1)[-1]
    assert HOOK not in caplog.text
    assert token not in caplog.text


def test_deploy_summary_carries_outcomes_only(captured, monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    requests, client = captured
    outcomes = {"nlA00": Outcome(Status.OK), "mskA10": Outcome(Status.FAILED, "rolled back")}
    summary_file = tmp_path / "summary.txt"

    NotifyController(cast(Any, None)).deploy_summary(
        DiscordNotify(webhook_url=HOOK),
        title="Deploy",
        outcomes=outcomes,
        scope="all nodes",
        commit="c" * 40,
        run_id="run1",
        extra={},
        summary_file=summary_file,
        client=client,
    )

    content = requests[0].content.decode(errors="replace")
    assert "mskA10" in content and "rolled back" in content
    assert "---" not in content and "+++" not in content
    lines = summary_file.read_text().splitlines()
    assert len(lines) == len(outcomes)
    assert all(
        line.startswith(node_id)
        for line, node_id in zip(
            lines,
            outcomes,
            strict=True,
        )
    )
    assert requests[0].headers["content-type"].startswith("multipart/form-data")
    assert 'name="files[0]"' in content
    assert 'name="payload_json"' in content
