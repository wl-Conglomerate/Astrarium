"""Versions part of `arium fleet status`."""

import asyncio

import pytest

from astrarium.components.rollout.transport import CommandResult
from astrarium.components.secrets.masking import ValueMasker
from astrarium.components.versions.controller import status_versions
from astrarium.components.versions.report import status_entries
from tests.support.fleet import NO_LOCK, ScriptedTransport, fleet, manifest_from


pytestmark = pytest.mark.unit


def _cells(transport, *, all_components=False):
    nodes = fleet()
    manifest = manifest_from(nodes, versions={"telemt": "3.5.7"})
    return asyncio.run(
        status_versions(
            transport,
            nodes,
            manifest,
            NO_LOCK,
            sorted(nodes),
            all_components=all_components,
            masker=ValueMasker(),
        )
    )


def test_status_flags_version_mismatch_and_never_logs_into_bastions_as_deploy_user():
    reply = CommandResult(
        rc=0,
        stdout="@@astrarium telemt\ntelemt 3.5.6\n",
        stderr="",
    )
    transport = ScriptedTransport(replies={("plsA00", "@@astrarium"): reply})
    shown, mismatched = status_entries(_cells(transport)["plsA00"])
    assert mismatched == ["telemt"]
    assert "3.5.6" in shown["telemt"]
    assert "edge" not in {node_id for node_id, _ in transport.calls}


def test_failed_version_probe_on_a_reachable_node_is_a_mismatch():
    transport = ScriptedTransport(
        replies={
            ("plsA00", "@@astrarium"): CommandResult(
                rc=1,
                stdout="",
                stderr="",
            )
        }
    )
    assert status_entries(_cells(transport)["plsA00"])[1] == ["telemt"]


def test_all_adds_nullforge_defaults_to_the_status_columns():
    default = {cell.component for cell in _cells(ScriptedTransport())["plsA00"]}
    everything = {cell.component for cell in _cells(ScriptedTransport(), all_components=True)["plsA00"]}
    assert "curl" not in default
    assert {"telemt", "curl"} <= everything
