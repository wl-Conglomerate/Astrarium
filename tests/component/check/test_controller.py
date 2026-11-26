"""check end to end on git repos with fake xray and haproxy."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from astrarium.app import AstrariumApp
from astrarium.components.check import controller as check_controller
from astrarium.components.check.controller import CheckOptions
from astrarium.components.manifest.models import Arch, VersionPin
from astrarium.components.rollout.artifacts import XrayArtifact
from astrarium.errors import InvalidManifest, Refused
from tests.support.check_repo import (
    AGE_A,
    TOPOLOGY,
    XRAY_SHA,
    make_check_repo,
    manifest_data,
    sops_config_text,
    write_deployment,
)
from tests.support.deployment import git, git_commit_all


pytestmark = pytest.mark.component

ARIUM = Path(sys.executable).with_name("arium")

FAKE_XRAY = """#!/bin/sh
[ "$1 $2 $3" = "run -test -config" ] || exit 2
[ -f "$XRAY_LOCATION_ASSET/geoip.dat" ] && [ -f "$XRAY_LOCATION_ASSET/geosite.dat" ] \\
  || { echo "geo data missing" >&2; exit 23; }
if grep -q "/usr/local/etc/xray/certs/" "$4"; then echo "certificate path not replaced" >&2; exit 23; fi
if grep -q "FAILME" "$4"; then echo "Failed to build config: FAILME" >&2; exit 23; fi
exit 0
"""

FAKE_HAPROXY = """#!/bin/sh
[ "$1" = "-v" ] && { echo "HAProxy version 3.2.0 2026/01/01 - https://haproxy.org/"; exit 0; }
[ "$1 $2" = "-c -f" ] || exit 2
if grep -q "/run/haproxy/admin.sock" "$3"; then echo "socket not moved" >&2; exit 1; fi
exit 0
"""


@dataclass(frozen=True)
class Tools:
    xray: Path
    haproxy: Path
    geo: Path

    def options(self) -> CheckOptions:
        return CheckOptions(
            base="main",
            xray_bin=self.xray,
            haproxy_bin=self.haproxy,
            geo_dir=self.geo,
        )


@dataclass(frozen=True)
class StubResolver:
    binary: Path
    good: str

    def resolve(self, pin: VersionPin, arch: Arch, provided: Mapping[Arch, Path]) -> XrayArtifact:
        if pin != self.good:
            raise Refused(f"no artifact for {pin}")
        return XrayArtifact(
            arch=arch,
            binary=self.binary,
            sha256="0" * 64,
            label=str(pin),
        )


class ReachableUpstream:
    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool:
        return True


def _script(path: Path, text: str) -> Path:
    path.write_text(text)
    path.chmod(0o755)
    return path


@pytest.fixture
def tools(tmp_path: Path) -> Tools:
    geo = tmp_path / "geo"
    geo.mkdir()
    for name in ("geoip.dat", "geosite.dat"):
        (geo / name).write_bytes(b"geo")
    xray = _script(tmp_path / "xray", FAKE_XRAY)
    haproxy = _script(tmp_path / "haproxy", FAKE_HAPROXY)
    return Tools(
        xray=xray,
        haproxy=haproxy,
        geo=geo,
    )


def _branch_with_topology(root: Path, topology: str) -> None:
    git(
        root,
        "switch",
        "-q",
        "-c",
        "feature",
    )
    (root / "topology.yaml").write_text(topology)


def test_only_really_changed_nodes_show_diffs(tmp_path: Path, tools: Tools) -> None:
    root = make_check_repo(tmp_path / "repo")
    _branch_with_topology(root, TOPOLOGY.replace("path: /tls/", "path: /tls2/"))
    (root / "runes").mkdir()
    (root / "runes" / "extra.py").write_text("print('rune')\n")
    git_commit_all(root, "feature")

    report = AstrariumApp(root).check.run(tools.options())

    states = {diff.node_id: diff.state for diff in report.nodes}
    assert states == {
        "nlA00": "unchanged",
        "mskA00": "unchanged",
        "spbA00": "changed",
    }
    spb = next(diff for diff in report.nodes if diff.node_id == "spbA00")
    assert "/tls2/" in spb.config_diff
    assert "runes/extra.py" in report.code_diff
    assert not report.failed
    passed = {(result.node_id, result.kind) for result in report.tests if result.status == "passed"}
    assert passed == {(node, kind) for node in states for kind in ("xray", "haproxy")}


def test_base_without_deployment_reports_every_node_added(tmp_path: Path, tools: Tools) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "README.md").write_text("new deployment\n")
    git_commit_all(root, "empty")
    git(
        root,
        "switch",
        "-q",
        "-c",
        "feature",
    )
    write_deployment(root)
    git_commit_all(root, "deployment")

    report = AstrariumApp(root).check.run(tools.options())

    assert {diff.state for diff in report.nodes} == {"added"}
    assert report.warnings
    assert report.overlay.added


def test_failing_config_test_exits_1_and_writes_report(tmp_path: Path, tools: Tools) -> None:
    root = make_check_repo(tmp_path / "repo")
    _branch_with_topology(root, TOPOLOGY.replace("path: /tls/", "path: /FAILME/"))
    git_commit_all(root, "broken")
    report_md = tmp_path / "report.md"

    proc = subprocess.run(
        [
            str(ARIUM),
            "--repo",
            str(root),
            "repo",
            "check",
            "--base",
            "main",
            "--xray-bin",
            str(tools.xray),
            "--haproxy-bin",
            str(tools.haproxy),
            "--geo-dir",
            str(tools.geo),
            "--report-md",
            str(report_md),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert report_md.read_text().startswith("<!-- astrarium-check -->")


def test_each_node_is_tested_with_its_pinned_xray(
    tmp_path: Path,
    tools: Tools,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = manifest_data()
    del manifest["versions"]
    manifest["nodes"]["nlA00"]["overrides"] = {"versions": {"xray": f"main@{XRAY_SHA}"}}
    release = {"version": "v26.9.9", "sha256": {"x86_64": "0" * 64}}
    manifest["nodes"]["mskA00"]["overrides"] = {"versions": {"xray": release}}
    root = make_check_repo(tmp_path / "repo", manifest=manifest)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        check_controller,
        "machine_arch",
        lambda: "x86_64",
    )
    opts = CheckOptions(
        base="main",
        haproxy_bin=tools.haproxy,
        geo_dir=tools.geo,
    )

    report = AstrariumApp(root).check.run(opts, resolver=StubResolver(tools.xray, f"main@{XRAY_SHA}"))

    statuses = {result.node_id: result.status for result in report.tests if result.kind == "xray"}
    assert statuses == {
        "nlA00": "passed",
        "mskA00": "failed",
        "spbA00": "skipped",
    }


def test_release_pin_without_runner_arch_sha_skips_with_warning(
    tmp_path: Path,
    tools: Tools,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = manifest_data()
    manifest["versions"]["xray"] = {"version": "v26.9.9", "sha256": {"aarch64": "0" * 64}}
    root = make_check_repo(tmp_path / "repo", manifest=manifest)
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        check_controller,
        "machine_arch",
        lambda: "x86_64",
    )
    opts = CheckOptions(
        base="main",
        haproxy_bin=tools.haproxy,
        geo_dir=tools.geo,
    )

    report = AstrariumApp(root).check.run(opts)

    statuses = {result.node_id: result.status for result in report.tests if result.kind == "xray"}
    assert statuses == {
        "nlA00": "skipped",
        "mskA00": "skipped",
        "spbA00": "skipped",
    }
    assert not report.failed
    assert any("v26.9.9" in warning and "x86_64" in warning for warning in report.warnings)


def test_topology_node_missing_from_manifest_is_invalid(tmp_path: Path, tools: Tools) -> None:
    manifest = manifest_data()
    del manifest["nodes"]["spbA00"]
    root = make_check_repo(tmp_path / "repo", manifest=manifest)

    with pytest.raises(InvalidManifest):
        AstrariumApp(root).check.run(tools.options())


def test_base_with_non_utf8_secrets_files_still_writes_report(tmp_path: Path, tools: Tools) -> None:
    root = make_check_repo(tmp_path / "repo")
    (root / "secrets" / "backup.age").write_bytes(b"\xff\xfe\x00binary")
    (root / "secrets" / "keys" / "legacy.yaml").write_bytes(b"\xff\xfe: not utf-8\n")
    git_commit_all(root, "bad main")
    git(
        root,
        "switch",
        "-q",
        "-c",
        "feature",
    )
    (root / "secrets" / "keys" / "legacy.yaml").unlink()
    git_commit_all(root, "repair")
    report_md = tmp_path / "report.md"

    report = AstrariumApp(root).check.run(replace(tools.options(), report_md=report_md))

    assert report_md.is_file()
    assert {diff.state for diff in report.nodes} == {"unchanged"}
    assert any("secrets/keys/legacy.yaml" in warning for warning in report.warnings)


def test_malformed_base_sops_config_is_compared_as_empty_with_warning(tmp_path: Path, tools: Tools) -> None:
    root = make_check_repo(tmp_path / "repo")
    (root / ".sops.yaml").write_text("creation_rules:\n")
    git_commit_all(root, "bad main")
    git(
        root,
        "switch",
        "-q",
        "-c",
        "feature",
    )
    (root / ".sops.yaml").write_text(sops_config_text(AGE_A))
    git_commit_all(root, "repair")

    report = AstrariumApp(root).check.run(tools.options())

    assert report.recipients.config.added == [AGE_A]
    assert any(".sops.yaml" in warning for warning in report.warnings)


def test_check_tests_nodes_on_built_main_pin_and_skips_nodes_on_others(
    tmp_path: Path,
    tools: Tools,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    other = "f" * 40
    manifest = manifest_data()
    manifest["nodes"]["mskA00"]["overrides"] = {"versions": {"xray": f"main@{other}"}}
    app = AstrariumApp(make_check_repo(tmp_path / "repo", manifest=manifest))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(
        check_controller,
        "machine_arch",
        lambda: "x86_64",
    )
    opts = CheckOptions(
        base="main",
        haproxy_bin=tools.haproxy,
        geo_dir=tools.geo,
    )

    (build,) = app.check.xray_builds(
        "check",
        "x86_64",
        upstream=ReachableUpstream(),
    )
    report = app.check.run(opts, resolver=StubResolver(tools.xray, f"main@{build.sha}"))

    on_build = {"mskA00"} if build.sha == other else {"nlA00", "spbA00"}
    statuses = {result.node_id: result.status for result in report.tests if result.kind == "xray"}
    assert {node for node, status in statuses.items() if status == "passed"} == on_build
    skipped = {node for node, status in statuses.items() if status == "skipped"}
    assert skipped == set(statuses) - on_build
    assert any(all(node in warning for node in skipped) for warning in report.warnings)


def test_xray_tests_skip_on_non_linux(tmp_path: Path, tools: Tools, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    root = make_check_repo(tmp_path / "repo", manifest=manifest_data())
    opts = CheckOptions(
        base="main",
        haproxy_bin=tools.haproxy,
        geo_dir=tools.geo,
    )
    report = AstrariumApp(root).check.run(opts)
    statuses = {result.node_id: result.status for result in report.tests if result.kind == "xray"}
    assert statuses
    assert set(statuses.values()) == {"skipped"}
