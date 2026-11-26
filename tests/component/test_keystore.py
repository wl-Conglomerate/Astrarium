"""Encrypted key files."""

from pathlib import Path

import pytest
import yaml

from astrarium.components.secrets.keystore import KeyStore
from astrarium.errors import ExternalToolError
from astrarium.repo import Repo
from tests.support.fake_sops import FakeSops


pytestmark = pytest.mark.component

KEYS = {
    "reality_private_key": "private-key-material-0001",
    "reality_public_key": "pub",
    "decryption": "d",
    "encryption": "e",
}


class _FailingSops(FakeSops):
    """Encrypt always fails, as real sops would with no matching creation rule."""

    def encrypt(self, plaintext: bytes, *, filename_override: Path, cwd: Path) -> bytes:
        raise ExternalToolError("sops encrypt failed: no matching creation rules")


class _CwdRecordingSops(FakeSops):
    """FakeSops that also records encrypt cwd."""

    def __init__(self) -> None:
        super().__init__()
        self.encrypt_cwds: list[Path] = []

    def encrypt(self, plaintext: bytes, *, filename_override: Path, cwd: Path) -> bytes:
        self.encrypt_cwds.append(cwd)
        return super().encrypt(
            plaintext,
            filename_override=filename_override,
            cwd=cwd,
        )


def test_store_encrypts_with_repo_relative_filename_override_from_repo_root(tmp_path: Path):
    repo = Repo(tmp_path / "repo")
    plaintext = tmp_path / "runtime" / "nlA00.yaml"
    plaintext.parent.mkdir()
    plaintext.write_text(yaml.safe_dump(KEYS))
    sops = _CwdRecordingSops()
    KeyStore(repo, sops).store("nlA00", plaintext)
    assert sops.calls == [("encrypt", "secrets/keys/nlA00.yaml")]
    assert sops.encrypt_cwds == [repo.root]


def test_store_writes_only_ciphertext_atomically(tmp_path: Path):
    repo = Repo(tmp_path)
    plaintext = tmp_path / "runtime" / "nlA00.yaml"
    plaintext.parent.mkdir()
    plaintext.write_text(yaml.safe_dump(KEYS))
    store = KeyStore(repo, FakeSops())
    store.store("nlA00", plaintext)
    written = repo.key_file("nlA00")
    assert "private-key-material-0001" not in written.read_text()
    assert [path.name for path in repo.keys_dir.iterdir()] == ["nlA00.yaml"]


def test_store_leaves_no_plaintext_under_secrets_when_encrypt_fails(tmp_path: Path):
    repo = Repo(tmp_path)
    plaintext = tmp_path / "runtime" / "nlA00.yaml"
    plaintext.parent.mkdir()
    plaintext.write_text(yaml.safe_dump(KEYS))
    store = KeyStore(repo, _FailingSops())
    with pytest.raises(ExternalToolError):
        store.store("nlA00", plaintext)
    assert not repo.secrets_dir.exists() or not any(repo.secrets_dir.rglob("*"))


def test_decrypt_all_writes_private_plaintext_copies(tmp_path: Path):
    repo = Repo(tmp_path)
    sops = FakeSops()
    plaintext = tmp_path / "nlA00.plain.yaml"
    plaintext.write_text(yaml.safe_dump(KEYS))
    KeyStore(repo, sops).store("nlA00", plaintext)
    dest = KeyStore(repo, sops).decrypt_all(tmp_path / "runtime" / "keys")
    decrypted = dest / "nlA00.yaml"
    assert yaml.safe_load(decrypted.read_text()) == KEYS
    assert decrypted.stat().st_mode & 0o777 == 0o600


def test_missing_lists_ids_without_key_file(tmp_path: Path):
    repo = Repo(tmp_path)
    repo.keys_dir.mkdir(parents=True)
    repo.key_file("nlA00").write_text("sops: {}\n")
    assert KeyStore(repo, FakeSops()).missing(
        [
            "mskA00",
            "nlA00",
            "deA00",
        ]
    ) == ["deA00", "mskA00"]
