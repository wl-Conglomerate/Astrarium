"""Marker gates: payload tests need Linux GNU tools, integration tests need ASTRARIUM_IT_* environment."""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterator

import pytest

from astrarium.app import AstrariumApp


PAYLOAD_TOOLS = (
    "bash",
    "flock",
    "setsid",
    "sha256sum",
)


@pytest.fixture(autouse=True)
def outside_github_actions(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)


def _payload_skip_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "payload tests run on Linux only"
    missing = [tool for tool in PAYLOAD_TOOLS if shutil.which(tool) is None]
    return f"payload tests need {', '.join(missing)}" if missing else None


def _integration_skip_reason() -> str | None:
    if any(name.startswith("ASTRARIUM_IT_") for name in os.environ):
        return None
    return "integration tests need ASTRARIUM_IT_* environment"


@pytest.fixture(autouse=True)
def app_singleton_reset() -> Iterator[None]:
    """Fresh application singleton around every test, registered app never leaks across tests."""

    AstrariumApp.reset()
    yield
    AstrariumApp.reset()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    payload, integration = _payload_skip_reason(), _integration_skip_reason()
    for item in items:
        if payload and item.get_closest_marker("payload"):
            item.add_marker(pytest.mark.skip(reason=payload))
        if integration and item.get_closest_marker("integration"):
            item.add_marker(pytest.mark.skip(reason=integration))
