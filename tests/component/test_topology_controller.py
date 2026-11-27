"""Build pipeline: prepare, key checks, builds."""

import json
from pathlib import Path

import pytest
import yaml

from astrarium import __main__ as entry
from astrarium.app import AstrariumApp
from astrarium.errors import InvalidManifest, Refused, UsageProblem
from astrarium.runtime import RuntimeDir
from tests.support.deployment import NAMESPACE, TELEMT_SECRET, fixture_app, generate_keys, make_deployment
from tests.support.fake_sops import FakeSops


pytestmark = pytest.mark.component


def test_prepare_derives_nodes_injects_namespace_and_seeds_masker(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    app = fixture_app(root)
    with RuntimeDir() as runtime:
        ctx = app.topology.prepare(runtime, need_keys=True)
        assert set(ctx.nodes) == {
            "nlA00",
            "mskA00",
            "mskP00",
            "edge",
        }
        assert set(ctx.hexrift) == {"nlA00", "mskA00"}
        assert NAMESPACE in ctx.topology.read_text()
        assert runtime.path in ctx.topology.parents
        assert ctx.keys_dir is not None and sorted(p.name for p in ctx.keys_dir.iterdir()) == [
            "mskA00.yaml",
            "nlA00.yaml",
        ]
        private_key = yaml.safe_load((ctx.keys_dir / "nlA00.yaml").read_text())["reality_private_key"]
        masked = ctx.masker.mask(f"{NAMESPACE} {TELEMT_SECRET} {private_key}")
        assert not {
            NAMESPACE,
            TELEMT_SECRET,
            private_key,
        } & set(masked.split())


def test_prepare_registers_masks_with_github_actions_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    root = make_deployment(tmp_path / "repo")
    app = fixture_app(root)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    with RuntimeDir() as runtime:
        ctx = app.topology.prepare(runtime, need_keys=True)
        assert ctx.keys_dir is not None
        private_key = yaml.safe_load((ctx.keys_dir / "nlA00.yaml").read_text())["reality_private_key"]
    lines = capsys.readouterr().err.splitlines()
    assert lines and all(line.startswith("::add-mask::") for line in lines)
    assert {
        f"::add-mask::{value}"
        for value in (
            NAMESPACE,
            TELEMT_SECRET,
            private_key,
        )
    } <= set(lines)
    monkeypatch.delenv("GITHUB_ACTIONS")
    with RuntimeDir() as runtime:
        app.topology.prepare(runtime, need_keys=True)
    assert capsys.readouterr().err == ""


def test_build_json_command_keeps_stdout_pure_json_with_masks_on_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys,
):
    root = make_deployment(tmp_path / "repo")
    original_init = AstrariumApp.__init__

    def with_fake_sops(self: AstrariumApp, repo_path: Path | None = None) -> None:
        original_init(self, repo_path)
        self.sops = FakeSops()

    monkeypatch.setattr(
        AstrariumApp,
        "__init__",
        with_fake_sops,
    )
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    with pytest.raises(SystemExit) as caught:
        entry.main(
            [
                "--repo",
                str(root),
                "fleet",
                "build",
                "--out",
                str(tmp_path / "rendered"),
                "--json",
            ]
        )
    assert caught.value.code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["nodes"]
    assert [line for line in captured.err.splitlines() if line.startswith("::add-mask::")]

    monkeypatch.delenv("GITHUB_ACTIONS")
    with pytest.raises(SystemExit) as caught:
        entry.main(
            [
                "--repo",
                str(root),
                "fleet",
                "build",
                "--out",
                str(tmp_path / "rendered2"),
                "--json",
            ]
        )
    assert caught.value.code == 0
    captured = capsys.readouterr()
    json.loads(captured.out)
    assert not [line for line in captured.err.splitlines() if line.startswith("::add-mask::")]


def test_prepare_refuses_manifest_topology_mismatch(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    manifest = root / "astrarium.yaml"
    manifest.write_text(manifest.read_text().replace("  mskA00:\n    role: hub", "  mskA00:\n    role: exit"))
    with RuntimeDir() as runtime, pytest.raises(InvalidManifest):
        fixture_app(root).topology.prepare(runtime, need_keys=False)


def test_prepare_refuses_ip_only_manifest(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    manifest = root / "astrarium.yaml"
    manifest.write_text(manifest.read_text().replace("  domain: example.net\n", ""))
    with RuntimeDir() as runtime, pytest.raises(Refused):
        fixture_app(root).topology.prepare(runtime, need_keys=False)


def test_hub_build_requires_every_exit_key(tmp_path: Path):
    root = make_deployment(tmp_path / "repo", keys=False)
    app = fixture_app(root)
    generate_keys(
        root,
        app.sops,
        ["mskA00"],
    )
    with RuntimeDir() as runtime:
        ctx = app.topology.prepare(runtime, need_keys=True)
        with pytest.raises(Refused) as caught:
            app.topology.build(
                ctx,
                ["mskA00"],
                runtime.sub("out"),
            )
        assert "nlA00" in caught.value.message


def test_build_out_writes_private_files_outside_repo(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    out = tmp_path / "rendered"
    built, skipped = fixture_app(root).topology.build_out("@hub,mskP00", out)
    assert set(built) == {"mskA00"}
    assert set(skipped) == {"mskP00"}
    assert out.stat().st_mode & 0o777 == 0o700
    config = out / "mskA00" / "config.json"
    assert json.loads(config.read_text())["inbounds"]
    assert config.stat().st_mode & 0o777 == 0o600


def test_build_out_refuses_directory_inside_repo(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    with pytest.raises(UsageProblem):
        fixture_app(root).topology.build_out(None, root / "build")


def test_limit_entry_matching_nothing_is_refused(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    with pytest.raises(Refused):
        fixture_app(root).topology.build_out("nlA00,deA00", tmp_path / "out")


def test_hexrift_passthrough_runs_read_commands_only(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    app = fixture_app(root)
    assert app.topology.hexrift(["validate"]) == 0
    with pytest.raises(UsageProblem):
        app.topology.hexrift(
            [
                "gen-keys",
                "--all",
                "--force",
            ]
        )
