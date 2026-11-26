"""Node diffs: state from raw bytes, diffs masked."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from astrarium.components.check.report import diff_nodes
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.topology.bridge import BuiltNode


pytestmark = pytest.mark.component


def _built(root: Path, node_id: str, config: dict[str, Any]) -> BuiltNode:
    node_dir = root / node_id
    node_dir.mkdir(parents=True)
    (node_dir / "config.json").write_text(json.dumps(config, indent=2))
    (node_dir / "haproxy.cfg").write_text("global\n")
    return BuiltNode(
        node_id=node_id,
        config_json=node_dir / "config.json",
        haproxy_cfg=node_dir / "haproxy.cfg",
        haproxy_wanted=False,
    )


def test_diff_nodes_classifies_and_masks(tmp_path: Path) -> None:
    same = {"inbounds": [{"port": 443}]}
    before = {"inbounds": [{"port": 443, "settings": {"clients": [{"id": "11111111-aaaa"}]}}]}
    after = {"inbounds": [{"port": 8443, "settings": {"clients": [{"id": "22222222-bbbb"}]}}]}
    base = {
        name: _built(
            tmp_path / "base",
            name,
            cfg,
        )
        for name, cfg in (
            ("a", same),
            ("b", before),
            ("c", same),
        )
    }
    head = {
        name: _built(
            tmp_path / "head",
            name,
            cfg,
        )
        for name, cfg in (
            ("a", same),
            ("b", after),
            ("d", same),
        )
    }

    diffs = {
        diff.node_id: diff
        for diff in diff_nodes(
            base,
            head,
            ValueMasker(),
        )
    }

    assert {name: diff.state for name, diff in diffs.items()} == {
        "a": "unchanged",
        "b": "changed",
        "c": "removed",
        "d": "added",
    }
    assert "8443" in diffs["b"].config_diff
    assert "22222222-bbbb" not in diffs["b"].config_diff
    assert diffs["a"].config_diff == ""
