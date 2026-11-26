"""Throwaway key sets for base and head builds."""

from __future__ import annotations

from pathlib import Path

import pytest
from hexrift.app import HexRiftApp
from hexrift.components.keys.store import ENCRYPTION_DISABLED

from astrarium.components.check.throwaway import throwaway_keys
from astrarium.components.topology.bridge import open_hexrift
from tests.support.check_repo import TOPOLOGY, with_extra_exit, with_nl_keys_disabled


pytestmark = pytest.mark.component


def _app(path: Path, text: str) -> HexRiftApp:
    path.write_text(text)
    return open_hexrift(path)


def test_throwaway_keys_share_unchanged_nodes_and_follow_key_config(tmp_path: Path) -> None:
    base = _app(tmp_path / "base.yaml", with_extra_exit(TOPOLOGY))
    head = _app(tmp_path / "head.yaml", with_nl_keys_disabled(TOPOLOGY))

    head_keys, base_keys = throwaway_keys(
        head,
        base,
        tmp_path / "keys",
    )

    assert (base_keys / "mskA00.yaml").read_bytes() == (head_keys / "mskA00.yaml").read_bytes()
    # hexrift stores raw key material in files and disables encryption at render time, so judge
    # each side's set through render_keys: head nlA00 keyless, base nlA00 keyful
    assert head.keys.render_keys("nlA00", head_keys).encryption == ENCRYPTION_DISABLED
    assert base.keys.render_keys("nlA00", base_keys).encryption != ENCRYPTION_DISABLED
    assert (base_keys / "deA00.yaml").is_file()
    assert not (head_keys / "deA00.yaml").exists()
