"""Report parts: secrets and version changes, markdown size."""

from __future__ import annotations

from typing import Any

import pytest

from astrarium.components.check.report import (
    COMMENT_LIMIT,
    FENCE,
    MARKER,
    CheckReport,
    NodeDiff,
    PathChanges,
    RecipientChanges,
    SecretsFileChange,
    VersionChange,
    overlay_changes,
    recipient_changes,
    render_markdown,
    renderer_warning,
    secrets_file_changes,
    skip_reasons,
    tool_stack_changes,
    version_changes,
)
from astrarium.components.check.runners import CheckResult


pytestmark = pytest.mark.unit


def _report(tests: list[CheckResult], nodes: list[NodeDiff], **fields: Any) -> CheckReport:
    return CheckReport(
        base="aaaaaaaaaaaa",
        head="bbbbbbbbbbbb",
        nodes=nodes,
        tests=tests,
        versions=[],
        tool_stack=[],
        overlay=PathChanges(),
        recipients=RecipientChanges(),
        code_diff="",
        warnings=[],
        **fields,
    )


def test_overlay_changes_list_added_removed_and_reencrypted_paths() -> None:
    base = {
        "topology": {"namespace": "ENC[a]"},
        "notify": {"discord": {"webhook_url": "ENC[b]"}},
        "sops": {"mac": "ENC[m1]"},
    }
    head = {
        "topology": {"namespace": "ENC[c]"},
        "roles": {"pulsar": {"features": {"telemt": {"users": {"bob": "ENC[d]"}}}}},
        "sops": {"mac": "ENC[m2]"},
    }

    changes = overlay_changes(base, head)

    assert changes.added == ["roles.pulsar.features.telemt.users.bob"]
    assert changes.removed == ["notify.discord.webhook_url"]
    assert changes.changed == ["topology.namespace"]


def test_recipient_changes_cover_sops_config_and_file_metadata() -> None:
    base_config = {"creation_rules": [{"path_regex": "x", "age": "age1old,age1keep"}]}
    head_config = {
        "creation_rules": [{"path_regex": "x", "key_groups": [{"age": ["age1keep", "ssh-ed25519 AAAA new"]}]}]
    }
    base_recipients = [{"recipient": "age1old"}, {"recipient": "age1keep"}]
    base_files = {"secrets/astrarium.sops.yaml": {"sops": {"age": base_recipients}}}
    head_files = {
        "secrets/astrarium.sops.yaml": {"sops": {"age": [{"recipient": "age1keep"}]}},
        "secrets/keys/nlA00.yaml": {"sops": {"key_groups": [{"age": [{"recipient": "age1keep"}]}]}},
    }

    changes = recipient_changes(
        base_config,
        head_config,
        base_files,
        head_files,
    )

    assert changes.config.added == ["ssh-ed25519 AAAA new"]
    assert changes.config.removed == ["age1old"]
    assert changes.files["secrets/astrarium.sops.yaml"].removed == ["age1old"]
    assert changes.files["secrets/keys/nlA00.yaml"].added == ["age1keep"]


def test_version_changes_cover_node_overrides_and_tool_stack() -> None:
    base_raw = {
        "versions": {"xray": {"version": "v26.3.27", "sha256": {"x86_64": "a" * 64}}, "telemt": "3.5.7"},
        "nodes": {"mskP00": {"overrides": {"versions": {"telemt": "3.5.8"}}}},
    }
    head_raw = {"versions": {"xray": "main@" + "1" * 40, "telemt": "3.5.7"}, "nodes": {"mskP00": {}}}
    lock = 'version = 1\n\n[[package]]\nname = "hexrift"\nversion = "{v}"\n'

    pins = {change.path: change for change in version_changes(base_raw, head_raw)}
    stack = tool_stack_changes(lock.format(v="0.13.0"), lock.format(v="0.13.1"))

    assert set(pins) == {"versions.xray", "nodes.mskP00.overrides.versions.telemt"}
    assert pins["nodes.mskP00.overrides.versions.telemt"].after is None
    assert [
        (
            change.path,
            change.before,
            change.after,
        )
        for change in stack
    ] == [
        (
            "hexrift",
            "0.13.0",
            "0.13.1",
        )
    ]
    assert renderer_warning(stack)
    assert not renderer_warning(tool_stack_changes(lock.format(v="0.13.0"), lock.format(v="0.13.0")))


def test_version_changes_tolerates_pin_that_fails_current_schema() -> None:
    base_raw = {"versions": {"xray": {"version": "26.3.27", "sha256": {"x86_64": "A" * 64}}}}
    head_raw = {"versions": {"xray": {"version": "26.3.28", "sha256": {"x86_64": "A" * 64}}}}

    changes = version_changes(base_raw, head_raw)

    assert changes == [
        VersionChange(
            "versions.xray",
            "26.3.27",
            "26.3.28",
        )
    ]


def test_version_changes_show_sha256_change_for_unchanged_xray_tag() -> None:
    base_raw = {"versions": {"xray": {"version": "v26.3.27", "sha256": {"x86_64": "a" * 64}}}}
    head_raw = {"versions": {"xray": {"version": "v26.3.27", "sha256": {"x86_64": "b" * 64}}}}

    (change,) = version_changes(base_raw, head_raw)

    assert change.before != change.after
    assert change.before is not None and "v26.3.27" in change.before
    assert change.after is not None and "v26.3.27" in change.after


def test_markdown_fits_comment_limit_and_keeps_summary() -> None:
    big = "".join(f"+line {index} {'x' * 80}\n" for index in range(400))
    report = CheckReport(
        base="aaaaaaaaaaaa",
        head="bbbbbbbbbbbb",
        nodes=[
            NodeDiff(
                f"n{index}",
                "changed",
                config_diff=big,
            )
            for index in range(3)
        ],
        tests=[
            CheckResult(
                f"n{index}",
                "xray",
                "failed",
                "Failed to build config",
            )
            for index in range(3)
        ],
        versions=[],
        tool_stack=[],
        overlay=PathChanges(),
        recipients=RecipientChanges(),
        code_diff="",
        warnings=[],
    )

    text = render_markdown(report)

    assert len(text) <= COMMENT_LIMIT
    assert text.startswith(MARKER)
    assert all(f"| n{index} |" in text for index in range(3))
    assert text.count(f"{FENCE}diff") < 3


def test_failed_test_cell_shows_reason_line_and_output_goes_to_details() -> None:
    xray = (
        "Xray 26.9.9 (Xray, Penetrates Everything.) Custom (go1.26.3 linux/amd64)\n"
        "A unified platform for anti-censorship.\n"
        "Failed to start: main: failed to load config files: bad inbound\n"
    )
    haproxy = (
        "Trying to pull docker.io/library/haproxy:3.2...\n"
        "[ALERT]    (1) : config : parsing [/w/haproxy.cfg:3] : unknown keyword 'bogus'\n"
        "[ALERT]    (1) : config : Fatal errors found in configuration.\n"
    )
    tests = [
        CheckResult(
            "n1",
            "xray",
            "failed",
            xray,
        ),
        CheckResult(
            "n1",
            "haproxy",
            "failed",
            haproxy,
        ),
    ]

    text = render_markdown(_report(tests, [NodeDiff("n1", "unchanged")]))

    row = next(line for line in text.splitlines() if line.startswith("| n1 |"))
    assert "Failed to start" in row
    assert "unknown keyword" in row
    assert "Penetrates" not in row
    assert "Trying to pull" not in row
    details = text[text.index("<details>") :]
    assert "A unified platform for anti-censorship." in details
    assert "Fatal errors found in configuration." in details


def test_secrets_file_changes_list_new_ciphertext_and_name_key_file_node() -> None:
    base = {
        "secrets/astrarium.sops.yaml": {"topology": {"namespace": "ENC[a]"}, "sops": {"mac": "ENC[m1]"}},
        "secrets/keys/nlA00.yaml": {"reality": "ENC[b]", "sops": {"mac": "ENC[m2]"}},
        "secrets/keys/mskA00.yaml": {"reality": "ENC[c]", "sops": {"mac": "ENC[m3]", "lastmodified": "1"}},
    }
    head = {
        "secrets/astrarium.sops.yaml": {"topology": {"namespace": "ENC[a]"}, "sops": {"mac": "ENC[m9]"}},
        "secrets/keys/nlA00.yaml": {"reality": "ENC[z]", "sops": {"mac": "ENC[m8]"}},
        "secrets/keys/mskA00.yaml": {"reality": "ENC[c]", "sops": {"mac": "ENC[m3]", "lastmodified": "2"}},
    }

    changes = secrets_file_changes(base, head)

    assert set(changes) == {
        SecretsFileChange("secrets/astrarium.sops.yaml"),
        SecretsFileChange("secrets/keys/nlA00.yaml", node="nlA00"),
    }
    assert "secrets/keys/nlA00.yaml" in render_markdown(
        _report(
            [],
            [],
            secrets_files=changes,
        )
    )


def test_all_skipped_report_never_claims_passed_and_lists_skip_reasons() -> None:
    no_linux, no_haproxy = "xray release binaries need Linux", "no haproxy binary, podman or docker"
    tests = [
        CheckResult(
            "n1",
            "xray",
            "skipped",
            no_linux,
        ),
        CheckResult(
            "n2",
            "xray",
            "skipped",
            no_linux,
        ),
        CheckResult(
            "n1",
            "haproxy",
            "skipped",
            no_haproxy,
        ),
    ]
    report = _report(tests, [NodeDiff("n1", "unchanged"), NodeDiff("n2", "unchanged")])

    assert report.status == "skipped"
    assert "passed" not in render_markdown(report)
    assert set(skip_reasons(report)) == {no_linux, no_haproxy}
