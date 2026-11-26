"""versions bump: xray release hashes, HEAD pins, NullForge tags, tool stack through uv add."""

import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

from astrarium.components.manifest.loader import load_manifest
from astrarium.components.manifest.models import XrayRelease
from astrarium.components.rollout.artifacts import XRAY_REPO
from astrarium.components.versions import controller as versions_module
from astrarium.components.versions.controller import BumpOptions, uv_add
from astrarium.components.versions.registry import tool_stack_versions
from astrarium.errors import AstrariumError, ExternalToolError, Refused
from astrarium.repo import Repo
from tests.support.versions_upstream import ReleaseSource, make_release, versions_controller
from tests.support.wheels import build_wheel


pytestmark = pytest.mark.component

X64_DIGEST = "1" * 64

ARM_ZIP = b"xray arm64 archive"

MANIFEST = """\
# deployment manifest
deployment:
  name: test
  domain: example.net
  names:
    exit: aphelion
    hub: perigee
    pulsar: pulsar
# pins are reviewed in pull requests
versions:
  telemt: 3.5.6
nodes:
  nlA00:
    role: exit
    ipv4: 203.0.113.10
  nlA01:
    role: exit
    ipv4: 203.0.113.11
    arch: aarch64
  mskA10:
    role: hub
    ipv4: 203.0.113.30
  plsA00:
    role: pulsar
    ipv4: 203.0.113.40
"""

AARCH64_ONLY_MANIFEST = """\
deployment:
  name: test
  domain: example.net
  names:
    exit: aphelion
    hub: perigee
    pulsar: pulsar
nodes:
  nlA00:
    role: exit
    ipv4: 203.0.113.10
    arch: aarch64
  mskA10:
    role: hub
    ipv4: 203.0.113.30
    arch: aarch64
"""

PYPROJECT = """\
[project]
name = "deployment-test"
version = "0"
requires-python = ">=3.13"
dependencies = ["hexrift==0.13.0"]

[tool.uv]
package = false

[[tool.uv.index]]
name = "photon"
url = "{index}"
format = "flat"
explicit = true

[tool.uv.sources]
hexrift = {{ index = "photon" }}  # photon only
"""

LOCK = """\
version = 1
revision = 3
requires-python = ">=3.13"

[options]
resolution-mode = "lowest-direct"

[[package]]
name = "hexrift"
version = "0.13.0"
source = { registry = "https://photon.example.net/simple/" }
"""

BUMPED_LOCK = LOCK.replace('version = "0.13.0"', 'version = "0.13.1"')

DROPPED_UV_ENV = (
    "UV_CONFIG_FILE",
    "UV_CONSTRAINT",
    "UV_DEFAULT_INDEX",
    "UV_EXCLUDE_NEWER",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_FORK_STRATEGY",
    "UV_FROZEN",
    "UV_INDEX",
    "UV_INDEX_STRATEGY",
    "UV_INDEX_URL",
    "UV_KEYRING_PROVIDER",
    "UV_LOCKED",
    "UV_NO_CONFIG",
    "UV_NO_SOURCES",
    "UV_NO_SOURCES_PACKAGE",
    "UV_OFFLINE",
    "UV_PRERELEASE",
    "UV_PROJECT",
    "UV_RESOLUTION",
    "UV_WORKING_DIR",
)

KEPT_UV_ENV = {
    "UV_INDEX_PHOTON_USERNAME": "ci",
    "UV_INDEX_PHOTON_PASSWORD": "token",
    "UV_CACHE_DIR": "/cache",
}


def _repo(tmp_path):
    (tmp_path / "astrarium.yaml").write_text(MANIFEST, encoding="utf-8")
    return Repo(root=tmp_path)


def _xray_upstream():
    assets = {"Xray-linux-64.zip": f"sha256:{X64_DIGEST}", "Xray-linux-arm64-v8a.zip": None}
    source = ReleaseSource(
        releases={
            XRAY_REPO: [
                make_release(
                    "v26.9.9",
                    pre=True,
                    assets=assets,
                )
            ]
        }
    )
    source.files["https://example.invalid/v26.9.9/Xray-linux-arm64-v8a.zip"] = ARM_ZIP
    return source


def test_xray_release_bump_records_sha256_for_every_fleet_architecture(tmp_path):
    repo = _repo(tmp_path)
    versions_controller(repo, upstream=_xray_upstream()).bump(
        BumpOptions(
            "xray",
            "v26.9.9",
            None,
        )
    )
    expected = {"version": "v26.9.9", "sha256": {"x86_64": X64_DIGEST, "aarch64": hashlib.sha256(ARM_ZIP).hexdigest()}}
    assert load_manifest(repo, None).versions["xray"] == XrayRelease.model_validate(expected)
    assert "# pins are reviewed in pull requests" in repo.manifest.read_text(encoding="utf-8")


def test_xray_release_bump_always_records_x86_64_for_an_aarch64_only_fleet(tmp_path):
    (tmp_path / "astrarium.yaml").write_text(AARCH64_ONLY_MANIFEST, encoding="utf-8")
    repo = Repo(root=tmp_path)
    versions_controller(repo, upstream=_xray_upstream()).bump(
        BumpOptions(
            "xray",
            "v26.9.9",
            None,
        )
    )
    pin = load_manifest(repo, None).versions["xray"]
    assert isinstance(pin, XrayRelease)
    assert set(pin.sha256) == {"x86_64", "aarch64"}


def test_release_without_an_asset_for_a_fleet_architecture_is_refused(tmp_path):
    repo = _repo(tmp_path)
    source = ReleaseSource(releases={XRAY_REPO: [make_release("v26.9.9", assets={"Xray-linux-64.zip": X64_DIGEST})]})
    with pytest.raises(Refused):
        versions_controller(repo, upstream=source).bump(
            BumpOptions(
                "xray",
                "v26.9.9",
                None,
            )
        )
    assert repo.manifest.read_text(encoding="utf-8") == MANIFEST


def test_head_bump_resolves_latest_and_requires_a_commit_on_upstream_main(tmp_path):
    repo = _repo(tmp_path)
    head = "c" * 40
    source = ReleaseSource(heads={XRAY_REPO: head}, reachable={head})
    versions_controller(repo, upstream=source).bump(
        BumpOptions(
            "xray",
            "main@latest",
            "nlA00",
        )
    )
    assert load_manifest(repo, None).nodes["nlA00"].overrides.versions["xray"] == f"main@{head}"
    with pytest.raises(Refused):
        versions_controller(repo, upstream=source).bump(
            BumpOptions(
                "xray",
                "main@" + "d" * 40,
                None,
            )
        )


def test_nullforge_bump_checks_the_upstream_tag_form(tmp_path):
    repo = _repo(tmp_path)
    source = ReleaseSource(releases={"Diniboy1123/usque": [make_release("v4.3.0")]})
    versions_controller(repo, upstream=source).bump(
        BumpOptions(
            "usque",
            "4.3.0",
            "mskA10",
        )
    )
    assert (
        "release",
        "Diniboy1123/usque",
        "v4.3.0",
    ) in source.calls
    assert load_manifest(repo, None).nodes["mskA10"].overrides.versions["usque"] == "4.3.0"


@pytest.mark.parametrize(
    (
        "component",
        "version",
        "node",
    ),
    [
        (
            "telemt",
            "9.9.9",
            None,
        ),
        (
            "xray",
            "v26.9.9",
            "plsA00",
        ),
        (
            "nosuch",
            "1.0.0",
            None,
        ),
    ],
)
def test_bumps_that_cannot_apply_leave_the_manifest_untouched(tmp_path, component, version, node):
    repo = _repo(tmp_path)
    with pytest.raises(AstrariumError):
        versions_controller(repo, upstream=_xray_upstream()).bump(
            BumpOptions(
                component,
                version,
                node,
            )
        )
    assert repo.manifest.read_text(encoding="utf-8") == MANIFEST


def test_tool_stack_bump_runs_uv_add_and_keeps_the_photon_source(tmp_path, monkeypatch):
    uv = os.environ.get("UV", "") or shutil.which("uv")
    if not uv:
        pytest.skip("uv is not available")
    wheels = tmp_path / "wheels"
    for version in ("0.13.0", "0.13.1"):
        build_wheel(
            wheels,
            "hexrift",
            version,
        )
    repo = _repo(tmp_path)
    repo.pyproject.write_text(PYPROJECT.format(index=wheels.as_posix()), encoding="utf-8")
    monkeypatch.setenv("UV_NO_CONFIG", "1")
    monkeypatch.setenv("UV_OFFLINE", "1")
    monkeypatch.setenv("UV_CACHE_DIR", str(tmp_path / "uv-cache"))
    monkeypatch.setenv("UV_PYTHON", sys.executable)
    subprocess.run(
        [uv, "lock"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    result = versions_controller(repo).bump(
        BumpOptions(
            "hexrift",
            "0.13.1",
            None,
        )
    )
    assert (result.before, result.after) == ("0.13.0", "0.13.1")
    assert tool_stack_versions(repo.lockfile) == {"hexrift": "0.13.1"}
    pyproject = tomllib.loads(repo.pyproject.read_text(encoding="utf-8"))
    assert pyproject["tool"]["uv"]["sources"]["hexrift"]["index"] == "photon"


def test_uv_add_hides_operator_uv_config_and_keeps_index_credentials(tmp_path, monkeypatch):
    user_config = tmp_path / "user-config"
    (user_config / "uv").mkdir(parents=True)
    (user_config / "uv" / "uv.toml").write_text('index-url = "https://mirror.example.net/simple"\n', encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(user_config))
    monkeypatch.setenv("XDG_CONFIG_DIRS", str(user_config))
    for name in DROPPED_UV_ENV:
        monkeypatch.setenv(name, "1")
    for name, value in KEPT_UV_ENV.items():
        monkeypatch.setenv(name, value)
    calls = []

    def run(argv, **kwargs):
        env = kwargs["env"]
        config_dirs = {env["XDG_CONFIG_HOME"], env["XDG_CONFIG_DIRS"]}
        calls.append(
            (
                argv,
                env,
                {path: list(Path(path).iterdir()) for path in config_dirs},
            )
        )
        return subprocess.CompletedProcess(
            argv,
            0,
            "",
            "",
        )

    monkeypatch.setattr(
        versions_module.subprocess,
        "run",
        run,
    )
    uv_add(
        "uv",
        tmp_path,
        "hexrift",
        "0.13.1",
    )
    [
        (
            argv,
            env,
            config_dirs,
        )
    ] = calls
    assert "--no-sync" in argv
    assert "hexrift==0.13.1" in argv
    assert "--no-config" not in argv
    assert not set(DROPPED_UV_ENV) & set(env)
    assert {name: env.get(name) for name in KEPT_UV_ENV} == KEPT_UV_ENV
    assert str(user_config) not in config_dirs
    assert all(not entries for entries in config_dirs.values())


@pytest.mark.parametrize(
    ("lock_after", "uv_fails"),
    [
        (LOCK.replace('version = "0.13.0"', 'version = "0.13.2"'), False),
        (BUMPED_LOCK.replace('[options]\nresolution-mode = "lowest-direct"\n\n', ""), False),
        (BUMPED_LOCK, True),
    ],
    ids=[
        "other-version",
        "options-dropped",
        "uv-add-failed",
    ],
)
def test_tool_stack_bump_restores_pyproject_and_lock_on_failure(tmp_path, monkeypatch, lock_after, uv_fails):
    repo = _repo(tmp_path)
    pyproject = PYPROJECT.format(index="https://photon.example.net/simple/")
    repo.pyproject.write_text(pyproject, encoding="utf-8")
    repo.lockfile.write_text(LOCK, encoding="utf-8")
    before = {path: path.read_bytes() for path in (repo.pyproject, repo.lockfile)}

    def fake_uv_add(uv, project, package, version):
        repo.pyproject.write_text(pyproject.replace("hexrift==0.13.0", f"hexrift=={version}"), encoding="utf-8")
        repo.lockfile.write_text(lock_after, encoding="utf-8")
        if uv_fails:
            raise ExternalToolError("uv add failed")

    monkeypatch.setenv("UV", "uv")
    monkeypatch.setattr(
        versions_module,
        "uv_add",
        fake_uv_add,
    )
    with pytest.raises(ExternalToolError):
        versions_controller(repo).bump(
            BumpOptions(
                "hexrift",
                "0.13.1",
                None,
            )
        )
    assert {path: path.read_bytes() for path in before} == before
