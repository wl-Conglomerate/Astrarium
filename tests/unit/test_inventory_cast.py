"""NullForge cast argv, limit safety and pyinfra JSON parsing."""

from pathlib import Path

import pytest

from astrarium.components.inventory.cast import CastRunner, parse_cast_output, touches_ssh
from astrarium.errors import ExternalToolError, InvalidManifest, Refused
from tests.support.fake_cast import documents, dry_doc, results_doc


pytestmark = pytest.mark.unit


def _values(argv, flag):
    return [argv[index + 1] for index, item in enumerate(argv) if item == flag]


def test_argv_passes_one_limit_per_node_runes_in_order_and_json_output():
    argv = CastRunner(python="/venv/bin/python").argv(
        Path("/rt/inventory/astrarium_inventory.py"),
        ["nlA00", "mskA10"],
        ["/pkg/deploy_access.py", "telemt"],
        dry=False,
    )
    assert argv[:4] == [
        "/venv/bin/python",
        "-m",
        "nullforge.cli",
        "cast",
    ]
    assert _values(argv, "-i") == ["/rt/inventory/astrarium_inventory.py"]
    assert sorted(_values(argv, "--limit")) == ["mskA10", "nlA00"]
    assert _values(argv, "-r") == ["/pkg/deploy_access.py", "telemt"]
    assert "-y" in argv
    assert "--json" in argv
    assert "--dry" not in argv


def test_dry_argv_asks_for_dry_diff_and_full_cast_has_no_rune():
    argv = CastRunner(python="py").argv(
        Path("/rt/inv.py"),
        ["nlA00"],
        [],
        dry=True,
    )
    assert "--dry" in argv
    assert "--diff" in argv
    assert "-r" not in argv


@pytest.mark.parametrize(
    ("limits", "error"),
    [
        ([], Refused),
        (["nl*"], InvalidManifest),
        (["nlA0?"], InvalidManifest),
        (["hub"], InvalidManifest),
        (["all"], InvalidManifest),
        (["exit"], InvalidManifest),
        (["bastion"], InvalidManifest),
    ],
)
def test_limits_that_pyinfra_would_widen_are_refused(limits, error):
    with pytest.raises(error):
        CastRunner(python="py").argv(
            Path("/rt/inv.py"),
            limits,
            [],
            dry=False,
        )


def test_parse_merges_stages_and_keeps_op_names_without_args():
    stdout = documents(
        results_doc({"netsec | Enable UFW firewall": ["nlA00"]}, failed=["mskA10"]),
        results_doc({"deploy_access | Write sudoers": ["nlA00", "nlA01"]}),
    )
    failed, changed, stages = parse_cast_output(stdout)
    assert stages == 2
    assert failed == ["mskA10"]
    assert changed["nlA00"] == ["netsec | Enable UFW firewall", "deploy_access | Write sudoers"]
    assert changed["nlA01"] == ["deploy_access | Write sudoers"]
    assert not any("secret-arg" in name for names in changed.values() for name in names)


def test_parse_dry_run_reports_planned_and_conditional_changes():
    stdout = documents(
        dry_doc({"users | Add SSH keys": ["nlA00"]}, conditional={"netsec | Restart SSH on change": ["nlA01"]})
    )
    failed, changed, _ = parse_cast_output(stdout)
    assert failed == []
    assert changed == {"nlA00": ["users | Add SSH keys"], "nlA01": ["netsec | Restart SSH on change"]}


def test_non_json_stdout_fails_without_echoing_it():
    with pytest.raises(ExternalToolError) as info:
        parse_cast_output('telemt secret 0123456789abcdef\n{"plan": []}\n')
    assert "0123456789abcdef" not in f"{info.value.message} {info.value.hint}"


@pytest.mark.parametrize(
    "document",
    [
        {"plan": [], "results": []},
        {"plan": [], "results": {"operations": ["op"]}},
        {"plan": ["op"], "results": None},
        {"plan": 5, "results": None},
        {"plan": [{"names": None, "hosts_with_change": ["nlA00"]}], "results": None},
    ],
)
def test_json_shape_drift_is_an_external_tool_error(document):
    with pytest.raises(ExternalToolError):
        parse_cast_output(documents(document))


@pytest.mark.parametrize(
    ("name", "touched"),
    [
        ("netsec | Enable UFW firewall", True),
        ("/opt/astrarium/runes/deploy_access.py | Write github_actions sudoers policy", True),
        ("users | Add SSH keys for core", True),
        ("telemt | Deploy telemt configuration", False),
        ("Install packages", False),
    ],
)
def test_ssh_sensitive_changes_are_detected_by_rune_label(name, touched):
    assert touches_ssh({"nlA00": [name]}, ["nlA00"]) is touched
