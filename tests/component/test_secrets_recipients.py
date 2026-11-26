"""`arium secrets recipients add|remove`."""

from pathlib import Path

import pytest
import yaml

from astrarium.components.secrets.recipients import SopsConfig, normalize_recipient
from astrarium.errors import ExitCode, ExternalToolError, PartialFailure, Refused, UsageProblem
from tests.support.deployment import fixture_app, make_deployment
from tests.support.fake_sops import FakeSops, write_encrypted


pytestmark = pytest.mark.component

OLD = "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"

NEW = "age1pppppppppppppppppppppppppppppppppppppppppppppppppppppppppp"

UNKNOWN = "age1" + "z" * 58

SSH = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH laptop"


def _fake_age_secret_key() -> str:
    return "AGE-SECRET-KEY-1" + "FAKE" * 15 + "FAKE"


def _fake_ssh_private_key_block() -> str:
    """Shape of OpenSSH private key block, never real: built at runtime, no full pattern in source."""

    marker = "PRIVATE KEY"
    body = "Zm" + "FrZS1wcml2YXRlLWtleS1ib2R5"
    return f"-----BEGIN OPENSSH {marker}-----\n{body}\n-----END OPENSSH {marker}-----\n"


class _FailingSops(FakeSops):
    """rotate raises ExternalToolError for one file, as sops would for one it cannot decrypt."""

    def __init__(self, fails_on: str):
        super().__init__()
        self.fails_on = fails_on

    def rotate(self, path: Path) -> None:
        if path.name == self.fails_on:
            raise ExternalToolError(f"sops rotate failed (exit 1): {path.name} could not be decrypted")
        super().rotate(path)


class _FailingUpdatekeysSops(FakeSops):
    """updatekeys raises ExternalToolError for one file, as sops would if it could not rewrap it."""

    def __init__(self, fails_on: str):
        super().__init__()
        self.fails_on = fails_on

    def updatekeys(self, path: Path) -> None:
        if path.name == self.fails_on:
            raise ExternalToolError(f"sops updatekeys failed (exit 1): {path.name} could not be rewrapped")
        super().updatekeys(path)


def test_add_updates_config_and_rewraps_every_file(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    sops = FakeSops()
    app = fixture_app(root, sops)
    change = app.secrets.add_recipients([NEW, SSH])
    assert change.recipients == [
        OLD,
        NEW,
        SSH,
    ]
    assert yaml.safe_load((root / ".sops.yaml").read_text())["creation_rules"][0]["age"] == f"{OLD},{NEW},{SSH}"
    updated = sorted(path for op, path in sops.calls if op == "updatekeys")
    assert len(updated) == 3
    assert not [op for op, _ in sops.calls if op == "rotate"]


def test_remove_rotates_data_key_of_every_file(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    sops = FakeSops()
    app = fixture_app(root, sops)
    app.secrets.add_recipients([NEW])
    change = app.secrets.remove_recipients([OLD])
    assert change.recipients == [NEW]
    rotated = [path for op, path in sops.calls if op == "rotate"]
    assert sorted(rotated) == sorted(str(path) for path in change.updated)


def test_list_form_is_kept_and_last_recipient_cannot_be_removed(tmp_path: Path):
    config = tmp_path / ".sops.yaml"
    config.write_text(f"# recipients\ncreation_rules:\n  - path_regex: secrets/.*\n    age:\n      - {OLD}\n")
    sops_config = SopsConfig(config)
    sops_config.update(add=[NEW])
    sops_config.save()
    assert yaml.safe_load(config.read_text())["creation_rules"][0]["age"] == [OLD, NEW]
    assert config.read_text().startswith("# recipients\n")
    with pytest.raises(UsageProblem):
        SopsConfig(config).update(remove=[OLD, NEW])


def test_pgp_only_rule_does_not_block_removal_from_age_rule(tmp_path: Path):
    config = tmp_path / ".sops.yaml"
    config.write_text(
        f"creation_rules:\n"
        f"  - path_regex: secrets/.*\n    age:\n      - {OLD}\n      - {NEW}\n"
        f"  - path_regex: other/.*\n    pgp: fake-pgp-fingerprint\n"
    )
    sops_config = SopsConfig(config)
    assert sops_config.update(remove=[OLD]) == [NEW]
    sops_config.save()
    assert yaml.safe_load(config.read_text())["creation_rules"] == [
        {"path_regex": "secrets/.*", "age": [NEW]},
        {"path_regex": "other/.*", "pgp": "fake-pgp-fingerprint"},
    ]


@pytest.mark.parametrize(
    "value",
    [
        "age1short",
        "ssh-rsa AAAAB3Nza x",
        "not a key",
        "ssh-ed25519 AAAAC3Nza a,b",
    ],
)
def test_invalid_recipients_are_refused(tmp_path: Path, value: str):
    root = make_deployment(tmp_path / "repo", keys=False)
    with pytest.raises(UsageProblem):
        fixture_app(root).secrets.add_recipients([value])


@pytest.mark.parametrize(
    "value",
    [
        _fake_age_secret_key(),
        _fake_ssh_private_key_block(),
        "fake-secretish-not-a-recipient",
    ],
)
def test_invalid_recipient_text_is_never_echoed(value: str):
    with pytest.raises(UsageProblem) as caught:
        normalize_recipient(value)
    shown = f"{caught.value.message} {caught.value.hint}"
    assert all(
        chunk not in shown
        for chunk in (
            "FAKEFAKE",
            "ZmFrZS1w",
            "fake-secretish",
        )
    )


def test_age_recipient_rejects_non_bech32_characters():
    # 'b' not in bech32 alphabet (also excludes 1, i, o), naive [0-9a-z] charset would accept it.
    with pytest.raises(UsageProblem):
        normalize_recipient("age1" + "b" * 58)


def test_remove_raises_partial_failure_when_sops_fails_partway(tmp_path: Path):
    # Files start out actually encrypted for OLD (their real recipient before any of this runs),
    # so rerun below finds OLD still in mskA00.yaml's own metadata (unrotated after failure).
    root = make_deployment(tmp_path / "repo", FakeSops(recipients=[OLD]))
    sops = _FailingSops(fails_on="mskA00.yaml")
    app = fixture_app(root, sops)
    app.secrets.add_recipients([NEW])

    with pytest.raises(PartialFailure) as excinfo:
        app.secrets.remove_recipients([OLD])

    error = excinfo.value
    assert error.exit_code == ExitCode.PARTIAL
    # .sops.yaml already reflects removal, done before any file touched.
    assert yaml.safe_load((root / ".sops.yaml").read_text())["creation_rules"][0]["age"] == NEW
    # message names done file plus remaining ones, including failed one.
    assert "astrarium.sops.yaml" in error.message
    assert "mskA00.yaml" in error.message
    assert "nlA00.yaml" in error.message
    # hint gives manual recovery commands for remaining files.
    assert error.hint is not None
    assert "sops updatekeys -y" in error.hint
    assert "sops rotate -i" in error.hint
    assert "mskA00.yaml" in error.hint
    assert "nlA00.yaml" in error.hint
    # rerun converges: OLD already gone from .sops.yaml, every file still re-wrapped and rotated.
    sops.fails_on = ""
    sops.calls.clear()
    change = app.secrets.remove_recipients([OLD])
    assert change.recipients == [NEW]
    files = [str(path) for path in change.updated]
    assert [path for op, path in sops.calls if op == "updatekeys"] == files
    assert [path for op, path in sops.calls if op == "rotate"] == files
    assert any(path.endswith("mskA00.yaml") for path in files)


def test_remove_converges_on_rerun_when_updatekeys_fails_on_the_last_file(tmp_path: Path):
    # Rotate runs before updatekeys: rotate never touches file's own sops.age metadata,
    # so when updatekeys (step rewriting it from .sops.yaml) fails on last file, that
    # file's metadata still names OLD and rerun still converges instead of refusing OLD as typo.
    root = make_deployment(tmp_path / "repo", FakeSops(recipients=[OLD]))
    sops = _FailingUpdatekeysSops(fails_on="")
    app = fixture_app(root, sops)
    app.secrets.add_recipients([NEW])

    sops.fails_on = "nlA00.yaml"
    sops.calls.clear()
    with pytest.raises(PartialFailure):
        app.secrets.remove_recipients([OLD])

    # rotate reached nlA00.yaml before its updatekeys failed: proves rotate-first order.
    calls_on_failure = list(sops.calls)
    assert any(op == "rotate" and path.endswith("nlA00.yaml") for op, path in calls_on_failure)
    assert not any(op == "updatekeys" and path.endswith("nlA00.yaml") for op, path in calls_on_failure)

    sops.fails_on = ""
    sops.calls.clear()
    change = app.secrets.remove_recipients([OLD])

    assert change.recipients == [NEW]
    files = [str(path) for path in change.updated]
    assert [path for op, path in sops.calls if op == "rotate"] == files
    assert [path for op, path in sops.calls if op == "updatekeys"] == files
    assert any(path.endswith("nlA00.yaml") for path in files)


def test_remove_covers_yml_files(tmp_path: Path):
    root = make_deployment(tmp_path / "repo")
    sops = FakeSops()
    app = fixture_app(root, sops)
    extra = write_encrypted(
        sops,
        root / "secrets" / "dns.yml",
        {"token": "fake-dns-token"},
        root,
    )
    (root / "secrets" / "keys" / ".gitkeep").write_text("")
    app.secrets.add_recipients([NEW])
    app.secrets.remove_recipients([OLD])
    assert ("rotate", str(extra)) in sops.calls
    assert not any(path.endswith(".gitkeep") for _, path in sops.calls)


def test_remove_refuses_recipient_absent_from_config_and_every_file(tmp_path: Path):
    sops = FakeSops(recipients=[OLD])
    root = make_deployment(tmp_path / "repo", sops)
    app = fixture_app(root, sops)
    config_before = (root / ".sops.yaml").read_text()

    with pytest.raises(UsageProblem) as caught:
        app.secrets.remove_recipients([UNKNOWN])

    assert caught.value.exit_code == ExitCode.INVALID
    assert (root / ".sops.yaml").read_text() == config_before
    assert not [op for op, _ in sops.calls if op in ("updatekeys", "rotate")]


def test_remove_converges_when_recipient_absent_from_config_but_present_in_file(tmp_path: Path):
    # Files are actually encrypted for OLD, .sops.yaml is then edited directly to drop OLD, as
    # prior partial-failure run would leave un-rotated file: OLD absent from config, still real
    # in that file's own metadata, so removal must still converge instead of refusing as unknown.
    sops = FakeSops(recipients=[OLD])
    root = make_deployment(tmp_path / "repo", sops)
    app = fixture_app(root, sops)
    config = SopsConfig(root / ".sops.yaml")
    config.update(add=[NEW])
    config.update(remove=[OLD])
    config.save()
    assert yaml.safe_load((root / ".sops.yaml").read_text())["creation_rules"][0]["age"] == NEW

    change = app.secrets.remove_recipients([OLD])

    assert change.recipients == [NEW]
    files = [str(path) for path in change.updated]
    assert [path for op, path in sops.calls if op == "rotate"] == files


@pytest.mark.parametrize(("name", "text"), [("notes.env", "TOKEN=plain\n"), ("dns.yml", "token: plain\n")])
def test_non_sops_file_under_secrets_refuses_before_config_changes(tmp_path: Path, name: str, text: str):
    root = make_deployment(tmp_path / "repo")
    sops = FakeSops()
    app = fixture_app(root, sops)
    app.secrets.add_recipients([NEW])
    (root / "secrets" / name).write_text(text)
    config_before = (root / ".sops.yaml").read_text()
    with pytest.raises(Refused) as caught:
        app.secrets.remove_recipients([OLD])
    assert caught.value.exit_code == ExitCode.REFUSED
    assert name in caught.value.message
    assert (root / ".sops.yaml").read_text() == config_before
    assert not [op for op, _ in sops.calls if op == "rotate"]
