"""`arium repo doctor` on fixture deployment."""

import shutil
from pathlib import Path

import pytest

from astrarium import __main__ as entry
from astrarium.app import AstrariumApp
from astrarium.errors import ExternalToolError
from astrarium.runtime import RuntimeDir
from tests.support.deployment import fixture_app, git_commit_all, make_deployment
from tests.support.fake_sops import FakeSops, write_encrypted


pytestmark = pytest.mark.component


@pytest.fixture(autouse=True)
def host_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        shutil,
        "which",
        lambda name, *args, **kwargs: f"/usr/bin/{name}",
    )
    monkeypatch.setattr(
        RuntimeDir,
        "leftovers",
        staticmethod(lambda: []),
    )


def test_fixture_deployment_passes_every_rule(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", git=True)
    failed = [check for check in fixture_app(root).doctor.run() if check.status == "fail"]
    assert failed == []


def test_doctor_reports_failures_with_exit_code_one(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    root = make_deployment(tmp_path / "repo", git=True)
    (root / "secrets" / "keys" / "mskA00.yaml").unlink()
    (root / "secrets" / "plain.yaml").write_text("token: not-encrypted\n")
    original = AstrariumApp.__init__

    def with_fake_sops(self, repo_path=None):
        original(self, repo_path)
        self.sops = FakeSops()

    monkeypatch.setattr(
        AstrariumApp,
        "__init__",
        with_fake_sops,
    )
    with pytest.raises(SystemExit) as caught:
        entry.main(
            [
                "--repo",
                str(root),
                "repo",
                "doctor",
                "--json",
            ]
        )
    out = capsys.readouterr().out
    assert caught.value.code == 1
    assert '"key files"' in out and '"secrets encrypted"' in out


def test_secrets_encrypted_covers_every_file_except_gitkeep(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", git=True)
    sops = FakeSops()
    (root / "secrets" / "keys" / ".gitkeep").write_text("")
    write_encrypted(
        sops,
        root / "secrets" / "dns.yml",
        {"token": "fake-dns-token"},
        root,
    )
    checks = {check.name: check for check in fixture_app(root, sops).doctor.run()}
    assert checks["secrets encrypted"].status == "pass"
    assert checks["secrets decryptable"].status == "pass"
    (root / "secrets" / "notes.env").write_text("TOKEN=plain\n")
    (root / "secrets" / "plain.yml").write_text("token: plain\n")
    check = {check.name: check for check in fixture_app(root, sops).doctor.run()}["secrets encrypted"]
    assert check.status == "fail"
    assert "notes.env" in check.detail and "plain.yml" in check.detail
    assert ".gitkeep" not in check.detail


@pytest.mark.parametrize(
    "zone",
    [
        "bad: [unterminated\n",
        "- not a mapping\n",
        "nlA00.aphelion: {type: A, values: 5}\n",
    ],
)
def test_malformed_dns_zone_is_dns_records_fail_not_abort(tmp_path: Path, zone: str):
    root = make_deployment(tmp_path / "repo", git=True)
    zone_file = root / "dns" / "zones" / "example.net.yaml"
    zone_file.parent.mkdir(parents=True)
    zone_file.write_text(zone)
    checks = {check.name: check for check in fixture_app(root).doctor.run()}
    assert checks["dns records"].status == "fail"
    assert "deploy workflow" in checks


def test_haproxy_check_fails_on_hexrift_build_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """HexRift build error -> haproxy check fail."""

    root = make_deployment(tmp_path / "repo", git=True)
    app = fixture_app(root)

    def boom(*args, **kwargs):
        raise ExternalToolError("hexrift build boom")

    monkeypatch.setattr("astrarium.components.doctor.controller.build_nodes", boom)
    checks = {check.name: check for check in app.doctor.run()}
    assert checks["haproxy"].status == "fail"


def test_reality_dest_warns_not_compared_when_git_show_fails(tmp_path: Path):
    """`git show` failure -> reality dest warn, not compared."""

    root = make_deployment(tmp_path / "repo")  # no git repo at all: `git show` fails
    checks = {check.name: check for check in fixture_app(root).doctor.run()}
    assert checks["reality dest"].status == "warn"


def test_reality_dest_warns_not_compared_when_git_not_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """git missing from PATH (FileNotFoundError) -> reality dest warn, other checks still reported."""

    root = make_deployment(tmp_path / "repo", git=True)

    def missing_git(*args, **kwargs):
        raise FileNotFoundError("[Errno 2] No such file or directory: 'git'")

    monkeypatch.setattr("astrarium.components.doctor.controller.subprocess.run", missing_git)
    checks = {check.name: check for check in fixture_app(root).doctor.run()}
    assert checks["reality dest"].status == "warn"


def test_reality_dest_warns_not_compared_when_committed_topology_malformed(tmp_path: Path):
    """Malformed committed topology.yaml -> reality dest warn, other checks still reported."""

    root = make_deployment(tmp_path / "repo", git=True)
    valid_topology = (root / "topology.yaml").read_text()
    (root / "topology.yaml").write_text("bad: [unterminated\n")
    git_commit_all(root, "malformed topology")
    (root / "topology.yaml").write_text(valid_topology)  # working tree valid again, HEAD stays malformed

    checks = {check.name: check for check in fixture_app(root).doctor.run()}
    assert checks["reality dest"].status == "warn"


def test_dns_ignored_names_reads_marker_comments(tmp_path: Path):
    from astrarium.components.doctor.controller import dns_ignored_names

    zone = tmp_path / "zone.yaml"
    zone.write_text(
        "agent.status:  # astrarium:ignore\n"
        "  - type: A\n"
        "    value: 192.0.2.10\n"
        "orrery:\n"
        "  # astrarium:ignore\n"
        "  - type: A\n"
        "    value: 192.0.2.11\n"
        "mskA00:\n"
        "  - type: A\n"
        "    value: 192.0.2.12\n"
    )
    assert dns_ignored_names(zone) == {"agent.status", "orrery"}
