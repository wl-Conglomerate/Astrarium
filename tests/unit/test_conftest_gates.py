"""Marker gates of tests/conftest.py."""

import pytest

from tests import conftest


pytestmark = pytest.mark.unit


def test_payload_tests_need_linux(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        conftest.sys,
        "platform",
        "darwin",
    )
    assert conftest._payload_skip_reason() is not None


def test_payload_tests_run_on_linux_with_gnu_tools(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        conftest.sys,
        "platform",
        "linux",
    )
    monkeypatch.setattr(
        conftest.shutil,
        "which",
        lambda tool: f"/usr/bin/{tool}",
    )
    assert conftest._payload_skip_reason() is None


def test_integration_tests_need_target_environment(monkeypatch: pytest.MonkeyPatch):
    for name in [name for name in conftest.os.environ if name.startswith("ASTRARIUM_IT_")]:
        monkeypatch.delenv(name)
    assert conftest._integration_skip_reason() is not None
    monkeypatch.setenv("ASTRARIUM_IT_HOST", "192.0.2.50")
    assert conftest._integration_skip_reason() is None
