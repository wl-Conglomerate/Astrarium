"""Console entry point: exit codes and global options."""

from collections.abc import Iterator
from pathlib import Path

import pytest
import rich_click as click

from astrarium import __main__ as entry
from astrarium.app import AstrariumApp, cli
from astrarium.errors import Refused


pytestmark = pytest.mark.component


@click.command("raise-refused")
def raise_refused() -> None:
    raise Refused("limit matched nothing")


@click.command("show-repo")
@click.pass_obj
def show_repo(app: AstrariumApp) -> None:
    click.echo(str(app.repo.root))


@click.command("return-seven")
def return_seven() -> int:
    return 7


@click.command("raise-key-error")
def raise_key_error() -> None:
    raise KeyError("nodes")


@pytest.fixture(autouse=True)
def probe_commands() -> Iterator[None]:
    cli.add_command(raise_refused)
    cli.add_command(show_repo)
    cli.add_command(return_seven)
    cli.add_command(raise_key_error)
    yield
    cli.commands.pop("raise-refused")
    cli.commands.pop("show-repo")
    cli.commands.pop("return-seven")
    cli.commands.pop("raise-key-error")


def _exit_code(argv: list[str]) -> int:
    with pytest.raises(SystemExit) as caught:
        entry.main(argv)
    return int(caught.value.code or 0)


def test_help_exits_zero():
    assert _exit_code(["--help"]) == 0


def test_astrarium_errors_map_to_their_exit_code(capsys):
    assert _exit_code(["raise-refused"]) == 4
    assert "limit matched nothing" in capsys.readouterr().err


def test_unknown_command_is_usage_error():
    assert _exit_code(["no-such-command"]) == 2


def test_repo_option_finds_deployment_root_from_subdirectory(tmp_path: Path, capsys):
    (tmp_path / "astrarium.yaml").write_text("deployment: {name: test}\nnodes: {}\n")
    nested = tmp_path / "secrets"
    nested.mkdir()
    assert (
        _exit_code(
            [
                "--repo",
                str(nested),
                "show-repo",
            ]
        )
        == 0
    )
    assert capsys.readouterr().out.strip() == str(tmp_path.resolve())


def test_missing_manifest_is_invalid(tmp_path: Path):
    assert (
        _exit_code(
            [
                "--repo",
                str(tmp_path),
                "show-repo",
            ]
        )
        == 2
    )


def test_command_return_value_is_not_used_as_exit_code():
    assert _exit_code(["return-seven"]) == 0


def test_unexpected_error_names_the_exception_type(capsys):
    assert _exit_code(["raise-key-error"]) == 1
    stderr = capsys.readouterr().err
    assert "KeyError" in stderr
    assert "nodes" in stderr


def test_unexpected_error_traceback_shown_only_when_verbose(capsys):
    assert _exit_code(["raise-key-error"]) == 1
    assert "Traceback" not in capsys.readouterr().err

    assert _exit_code(["--verbose", "raise-key-error"]) == 1
    assert "Traceback" in capsys.readouterr().err
