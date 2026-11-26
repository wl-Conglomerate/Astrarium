"""init pins running tool stack."""

from __future__ import annotations

import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest

from astrarium import __version__
from astrarium.app import AstrariumApp
from astrarium.components.init.controller import InitOptions
from tests.support.fake_sops import FakeSops
from tests.support.template import DEFAULT_ANSWERS, template_copy


pytestmark = pytest.mark.component

VERSION_ANSWERS = (
    "astrarium_version",
    "hexrift_version",
    "nullforge_version",
    "manticora_version",
)


def test_init_pins_running_tool_stack(tmp_path: Path) -> None:
    app = AstrariumApp(None)
    app.sops = FakeSops()
    answers = {key: value for key, value in DEFAULT_ANSWERS.items() if key not in VERSION_ANSWERS}
    dest = tmp_path / "deployment"
    opts = InitOptions(
        dest=dest,
        answers=answers,
        template=str(template_copy(tmp_path / "src")),
        defaults=True,
        run_tasks=False,
        quiet=True,
    )

    app.init.init(opts)

    dependencies = set(tomllib.loads((dest / "pyproject.toml").read_text())["project"]["dependencies"])
    assert dependencies == {
        f"astrarium=={__version__}",
        f"hexrift=={version('hexrift')}",
        f"nullforge=={version('nullforge')}",
    }
