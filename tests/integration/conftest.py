"""Integration fixtures: disposable target from ASTRARIUM_IT_* environment (mock evidence, never production).

Session fixture confirms MARKER_PATH on target matches ASTRARIUM_IT_TARGET_ID before any test: VM or
spare host opts in by writing marker by hand, so stray env pointing at real fleet host fails closed.
"""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from tests.support.it_target import TARGET_ID_ENV, ItConfigError, ItTarget, load_target, ssh_agent


@pytest.fixture(scope="session")
def it_target(tmp_path_factory: pytest.TempPathFactory) -> ItTarget:
    """Configured, marker-verified target: skip when no ASTRARIUM_IT_* variable is set, fail when variables
    incomplete or marker differs.
    """

    try:
        target = load_target(os.environ, tmp_path_factory.mktemp("it-ssh"))
    except ItConfigError as e:
        pytest.fail(str(e), pytrace=False)
    if target is None:
        pytest.skip('no ASTRARIUM_IT_* target: eval "$(tests/integration/target/it-target.sh start)"')
    try:
        target.check_marker(os.environ.get(TARGET_ID_ENV, ""))
    except AssertionError as e:
        pytest.fail(str(e), pytrace=False)
    return target


@pytest.fixture(scope="session")
def it_agent(it_target: ItTarget) -> Iterator[dict[str, str]]:
    """ssh-agent holding only target key: product SSH configs carry no IdentityFile."""

    with ssh_agent(it_target.key) as overlay:
        yield overlay
