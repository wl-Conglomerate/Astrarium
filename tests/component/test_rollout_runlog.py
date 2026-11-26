"""Masked private run log."""

import stat

import pytest

from astrarium.components.rollout.report import RunLog
from astrarium.components.secrets.masking import MASK, ValueMasker
from astrarium.repo import Repo


pytestmark = pytest.mark.component


def test_run_log_is_private_and_masked(tmp_path) -> None:
    masker = ValueMasker()
    masker.add("super-secret-token")

    log = RunLog(
        Repo(tmp_path),
        "run1",
        masker,
    )
    log.write("webhook super-secret-token failed")

    text = log.path.read_text()
    assert "super-secret-token" not in text
    assert "webhook" in text and "failed" in text and MASK in text
    assert stat.S_IMODE(log.path.stat().st_mode) == 0o600
