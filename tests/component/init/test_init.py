"""init: template copy plus encrypted fresh namespace."""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
import yaml

from astrarium.app import AstrariumApp
from astrarium.components.init import controller as init_controller
from astrarium.components.init.controller import InitOptions, bundled_template
from astrarium.errors import ExternalToolError, UsageProblem
from tests.support.fake_sops import FakeSops
from tests.support.template import DEFAULT_ANSWERS, template_copy


pytestmark = pytest.mark.component

NAMESPACE_PATTERN = re.compile(r"n[0-9a-f]{32}")

FAKE_UV = """#!/bin/sh
[ "$1" = "lock" ] || exit 2
pwd > "$FAKE_UV_RECORD"
printenv >> "$FAKE_UV_RECORD"
exit "${FAKE_UV_EXIT:-0}"
"""

UNSAFE_TEMPLATE_COPIER_YML = """\
_jinja_extensions:
  - jinja2.ext.do
deployment_name:
  type: str
  default: test
"""


def _app() -> AstrariumApp:
    app = AstrariumApp(None)
    app.sops = FakeSops()
    return app


def _options(tmp_path: Path, dest: Path, answers: dict[str, object], *, run_tasks: bool = False) -> InitOptions:
    source = template_copy(tmp_path / "src")
    return InitOptions(
        dest=dest,
        answers=answers,
        template=str(source),
        defaults=True,
        run_tasks=run_tasks,
        quiet=True,
    )


@pytest.fixture
def fake_uv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Fake `uv` first on PATH, recording cwd and env of `uv lock` into returned file."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(FAKE_UV)
    uv.chmod(0o755)
    record = tmp_path / "uv-record.txt"
    monkeypatch.delenv("UV", raising=False)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_UV_RECORD", str(record))
    return record


def test_init_renders_bundled_template(tmp_path: Path) -> None:
    app = _app()
    dest = tmp_path / "deployment"

    result = app.init.init(
        InitOptions(
            dest=dest,
            answers=DEFAULT_ANSWERS,
            defaults=True,
            run_tasks=False,
            quiet=True,
        )
    )

    assert (dest / "astrarium.yaml").is_file()
    assert result.has_dns is False
    namespace = yaml.safe_load(app.sops.decrypt(dest / "secrets" / "astrarium.sops.yaml"))["topology"]["namespace"]
    assert NAMESPACE_PATTERN.fullmatch(namespace)


def test_init_encrypts_fresh_namespace_that_no_other_file_holds(tmp_path: Path) -> None:
    app = _app()
    dest = tmp_path / "deployment"

    result = app.init.init(
        _options(
            tmp_path,
            dest,
            DEFAULT_ANSWERS,
        )
    )

    overlay = dest / "secrets" / "astrarium.sops.yaml"
    namespace = yaml.safe_load(app.sops.decrypt(overlay))["topology"]["namespace"]
    others = [path for path in dest.rglob("*") if path.is_file() and path != overlay]
    assert NAMESPACE_PATTERN.fullmatch(namespace)
    assert others
    assert all(namespace not in path.read_text() for path in others)
    assert "secrets/astrarium.sops.yaml" in result.files


def test_init_refuses_non_empty_directory(tmp_path: Path) -> None:
    dest = tmp_path / "deployment"
    dest.mkdir()
    (dest / "keep.txt").write_text("mine\n")

    with pytest.raises(UsageProblem):
        _app().init.init(
            _options(
                tmp_path,
                dest,
                DEFAULT_ANSWERS,
            )
        )

    assert sorted(path.name for path in dest.iterdir()) == ["keep.txt"]


def test_init_requires_manticora_pin_for_dns(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        init_controller,
        "tool_versions",
        lambda: {
            "astrarium_version": "0.1.0",
            "hexrift_version": "0.13.0",
            "nullforge_version": "0.4.0",
        },
    )
    answers = {key: value for key, value in DEFAULT_ANSWERS.items() if key != "manticora_version"}
    dest = tmp_path / "deployment"

    with pytest.raises(UsageProblem):
        _app().init.init(
            _options(
                tmp_path,
                dest,
                {**answers, "has_dns": True},
            )
        )

    assert not dest.exists()


def test_init_requires_tty_without_defaults(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    source = template_copy(tmp_path / "src")
    dest = tmp_path / "deployment"
    opts = InitOptions(
        dest=dest,
        answers=DEFAULT_ANSWERS,
        template=str(source),
        defaults=False,
        run_tasks=False,
        quiet=True,
    )

    with pytest.raises(UsageProblem):
        _app().init.init(opts)

    assert not dest.exists()


def test_init_removes_dest_it_created_when_uv_lock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_uv: Path,
) -> None:
    monkeypatch.setenv("FAKE_UV_EXIT", "1")
    dest = tmp_path / "deployment"

    with pytest.raises(ExternalToolError):
        _app().init.init(
            _options(
                tmp_path,
                dest,
                DEFAULT_ANSWERS,
                run_tasks=True,
            )
        )

    assert fake_uv.exists()
    assert not dest.exists()


def test_init_keeps_preexisting_empty_dest_on_failure(tmp_path: Path) -> None:
    dest = tmp_path / "deployment"
    dest.mkdir()

    with pytest.raises(UsageProblem):
        _app().init.init(
            _options(
                tmp_path,
                dest,
                {**DEFAULT_ANSWERS, "deployment_name": "Main Fleet"},
            )
        )

    assert list(dest.iterdir()) == []


def test_init_never_echoes_rejected_recipient(tmp_path: Path) -> None:
    bad_recipient = "age1short"
    answers = {**DEFAULT_ANSWERS, "age_recipients": bad_recipient}
    dest = tmp_path / "deployment"

    with pytest.raises(UsageProblem) as excinfo:
        _app().init.init(
            _options(
                tmp_path,
                dest,
                answers,
            )
        )

    assert bad_recipient not in str(excinfo.value)
    assert not dest.exists()


def test_init_runs_uv_lock_isolated_from_operator_uv_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fake_uv: Path,
) -> None:
    user_config = tmp_path / "operator-uv-config"
    (user_config / "uv").mkdir(parents=True)
    (user_config / "uv" / "uv.toml").write_text('index-url = "https://mirror.example.net/simple"\n', encoding="utf-8")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(user_config))
    monkeypatch.setenv("XDG_CONFIG_DIRS", str(user_config))
    monkeypatch.setenv("UV_NO_CONFIG", "1")
    monkeypatch.setenv("UV_OFFLINE", "1")

    dest = tmp_path / "deployment"

    _app().init.init(
        _options(
            tmp_path,
            dest,
            DEFAULT_ANSWERS,
            run_tasks=True,
        )
    )

    lines = fake_uv.read_text().splitlines()
    seen_cwd, env = lines[0], dict(line.split("=", 1) for line in lines[1:] if "=" in line)
    assert Path(seen_cwd) == dest.resolve()
    assert "UV_NO_CONFIG" not in env
    assert "UV_OFFLINE" not in env
    assert env["XDG_CONFIG_HOME"] != str(user_config)
    assert env["XDG_CONFIG_DIRS"] != str(user_config)


def test_init_refuses_photon_url_with_credentials(tmp_path: Path) -> None:
    token = "pypi-FAKE-TOKEN-0000"
    answers = {**DEFAULT_ANSWERS, "photon_url": f"https://__token__:{token}@photon.example.net/simple/"}
    dest = tmp_path / "deployment"

    with pytest.raises(UsageProblem) as caught:
        _app().init.init(
            _options(
                tmp_path,
                dest,
                answers,
            )
        )

    assert token not in f"{caught.value.message} {caught.value.hint}"
    assert not dest.exists()


def test_init_requires_trust_flag_for_custom_template_with_unsafe_features(tmp_path: Path) -> None:
    custom = tmp_path / "custom-template"
    custom.mkdir()
    (custom / "copier.yml").write_text(UNSAFE_TEMPLATE_COPIER_YML)
    (custom / "hello.txt.jinja").write_text("{{ deployment_name }}\n")
    dest = tmp_path / "deployment"

    with pytest.raises(UsageProblem):
        _app().init.init(
            InitOptions(
                dest=dest,
                template=str(custom),
                defaults=True,
                run_tasks=False,
                quiet=True,
            )
        )

    assert not dest.exists()


def test_init_allows_unsafe_custom_template_with_trust_flag(tmp_path: Path) -> None:
    custom = tmp_path / "custom-template"
    custom.mkdir()
    (custom / "copier.yml").write_text(UNSAFE_TEMPLATE_COPIER_YML)
    (custom / "hello.txt.jinja").write_text("{{ deployment_name }}\n")
    dest = tmp_path / "deployment"

    _app().init.init(
        InitOptions(
            dest=dest,
            template=str(custom),
            defaults=True,
            run_tasks=False,
            quiet=True,
            trust=True,
        )
    )

    assert (dest / "hello.txt").read_text() == "test\n"


def test_bundled_template_ships_in_package() -> None:
    with bundled_template() as source:
        root = Path(source)
        assert (root / "copier.yml").is_file()
        assert (root / "template" / "astrarium.yaml.jinja").is_file()
        assert (root / "template" / ".github" / "workflows" / "deploy.yaml").is_file()
