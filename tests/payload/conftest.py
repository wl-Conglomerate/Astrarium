"""Fake node fixture (payload marker gate in tests/conftest.py skips off Linux)."""

from pathlib import Path

import pytest

from tests.support.payload_node import FakeNode


@pytest.fixture
def node(tmp_path: Path) -> FakeNode:
    return FakeNode(tmp_path)
