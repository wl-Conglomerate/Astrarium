"""Discord webhook summary, never carries diffs."""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path

import httpx


LOG = logging.getLogger(__name__)

USERNAME = "Astrarium"

COLOR_OK = 3066993

COLOR_FAILED = 15158332

TITLE_LIMIT = 256

FIELD_NAME_LIMIT = 256

FIELD_VALUE_LIMIT = 1024

FIELDS_LIMIT = 25
"""Discord embed limits (developer docs, "Embed Limits")."""


def send_summary(
    webhook_url: str,
    thread_id: str | None,
    *,
    title: str,
    fields: Mapping[str, str],
    ok: bool,
    log: Path | None,
    client: httpx.Client | None = None,
) -> int:
    """POST one embed (plus optional text attachment), return HTTP status or 0 on network error."""

    embed = {
        "title": title[:TITLE_LIMIT],
        "color": COLOR_OK if ok else COLOR_FAILED,
        "fields": [
            {
                "name": name[:FIELD_NAME_LIMIT],
                "value": (value or "-")[:FIELD_VALUE_LIMIT],
                "inline": True,
            }
            for name, value in list(fields.items())[:FIELDS_LIMIT]
        ],
    }
    payload = {"username": USERNAME, "embeds": [embed]}
    params = {"thread_id": thread_id} if thread_id else None
    if client is None:
        client = httpx.Client(timeout=15.0)
    try:
        with client:
            if log is None:
                response = client.post(
                    webhook_url,
                    params=params,
                    json=payload,
                )
            else:
                response = client.post(
                    webhook_url,
                    params=params,
                    data={"payload_json": json.dumps(payload)},
                    files={
                        "files[0]": (
                            log.name,
                            log.read_bytes(),
                            "text/plain",
                        )
                    },
                )
    except (httpx.HTTPError, httpx.InvalidURL) as e:
        LOG.warning(f"discord webhook post failed: {str(e).replace(webhook_url, '***')}")
        return 0
    return response.status_code
