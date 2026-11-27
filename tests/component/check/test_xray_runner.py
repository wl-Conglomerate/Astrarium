"""xray -test runner: asset dir reaches xray, exit status maps to pass/fail."""

from __future__ import annotations

from pathlib import Path

import pytest

from astrarium.components.check.runners import run_xray_test


pytestmark = pytest.mark.component

FAKE_XRAY = """#!/bin/sh
[ "$1 $2 $3" = "run -test -config" ] || exit 2
[ -f "$XRAY_LOCATION_ASSET/geosite.dat" ] || { echo "no geosite" >&2; exit 23; }
if grep -q BROKEN "$4"; then echo "Failed to build config: BROKEN" >&2; exit 23; fi
exit 0
"""


def test_run_xray_test_passes_assets_and_reports_rejection(tmp_path: Path) -> None:
    xray = tmp_path / "xray"
    xray.write_text(FAKE_XRAY)
    xray.chmod(0o755)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "geosite.dat").write_bytes(b"geo")
    good = tmp_path / "good.json"
    good.write_text("{}")
    bad = tmp_path / "bad.json"
    bad.write_text('{"BROKEN": true}')

    assert run_xray_test(
        xray,
        good,
        assets,
    ) == (True, "")
    passed, output = run_xray_test(
        xray,
        bad,
        assets,
    )
    assert not passed
    assert "BROKEN" in output
