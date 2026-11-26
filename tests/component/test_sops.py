"""sops wrapper behaviour without real binary."""

import os
import stat
from pathlib import Path

import pytest

from astrarium.components.secrets.sops import Sops
from astrarium.errors import ExternalToolError


pytestmark = pytest.mark.component

PLAINTEXT_MARKER = "plaintext-that-must-not-leak"


def fake_binary(tmp_path: Path, script: str) -> Path:
    path = tmp_path / "sops"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_encrypt_failure_never_echoes_stderr(tmp_path: Path):
    binary = fake_binary(tmp_path, f'cat >/dev/null; echo "could not parse: {PLAINTEXT_MARKER}" >&2; exit 1\n')
    sops = Sops(binary=str(binary))
    with pytest.raises(ExternalToolError) as caught:
        sops.encrypt(
            PLAINTEXT_MARKER.encode(),
            filename_override=Path("secrets/x.yaml"),
            cwd=tmp_path,
        )
    assert PLAINTEXT_MARKER not in caught.value.message


def test_encrypt_passes_plaintext_on_stdin_with_filename_override(tmp_path: Path):
    binary = fake_binary(tmp_path, 'echo "$@" > args.txt; cat > stdin.txt; echo "ciphertext"\n')
    out = Sops(binary=str(binary)).encrypt(
        b"key: value\n",
        filename_override=Path("secrets/keys/nlA00.yaml"),
        cwd=tmp_path,
    )
    assert out == b"ciphertext\n"
    assert (tmp_path / "args.txt").read_text().split() == [
        "encrypt",
        "--filename-override",
        "secrets/keys/nlA00.yaml",
    ]
    assert (tmp_path / "stdin.txt").read_text() == "key: value\n"


@pytest.mark.parametrize(
    ("method", "argv"),
    [
        ("decrypt", ["decrypt"]),
        ("updatekeys", ["updatekeys", "-y"]),
        ("rotate", ["rotate", "-i"]),
    ],
)
def test_file_commands_take_absolute_path_and_run_in_file_dir(tmp_path: Path, method: str, argv: list[str]):
    record = tmp_path / "record.txt"
    binary = fake_binary(tmp_path, 'pwd -P > "$SOPS_RECORD"; printf "%s\\n" "$@" >> "$SOPS_RECORD"\n')
    target = tmp_path / "repo" / "secrets" / "keys" / "nlA00.yaml"
    target.parent.mkdir(parents=True)
    target.write_text("sops: {}\n")
    sops = Sops(binary=str(binary), env={**os.environ, "SOPS_RECORD": str(record)})
    getattr(sops, method)(target)
    cwd, *args = record.read_text().splitlines()
    assert Path(cwd) == target.resolve().parent
    assert args == [*argv, str(target.resolve())]


@pytest.mark.parametrize(
    "method",
    [
        "decrypt",
        "updatekeys",
        "rotate",
    ],
)
def test_file_command_failure_surfaces_last_stderr_line(tmp_path: Path, method: str):
    binary = fake_binary(tmp_path, 'echo "loading keys" >&2; echo "reason-token-42" >&2; exit 128\n')
    target = tmp_path / "x.yaml"
    target.write_text("sops: {}\n")
    with pytest.raises(ExternalToolError) as caught:
        getattr(Sops(binary=str(binary)), method)(target)
    assert "reason-token-42" in caught.value.message


def test_missing_binary_is_external_tool_error(tmp_path: Path):
    sops = Sops(binary="sops-does-not-exist", env={"PATH": str(tmp_path)})
    assert not sops.available()
    with pytest.raises(ExternalToolError):
        sops.decrypt(tmp_path / "x.yaml")


def test_has_metadata_detects_sops_files(tmp_path: Path):
    encrypted, plain = tmp_path / "a.yaml", tmp_path / "b.yaml"
    encrypted.write_text("key: ENC[AES256_GCM,data:x]\nsops:\n  version: 3.13.3\n")
    plain.write_text("key: value\n")
    assert Sops.has_metadata(encrypted)
    assert not Sops.has_metadata(plain)


def test_decrypt_with_missing_parent_dir_raises_external_tool_error(tmp_path: Path):
    binary = fake_binary(tmp_path, 'cat >/dev/null; echo "plaintext"\n')
    sops = Sops(binary=str(binary))
    missing = tmp_path / "missing-dir" / "x.yaml"
    with pytest.raises(ExternalToolError):
        sops.decrypt(missing)


def test_encrypt_with_missing_cwd_raises_external_tool_error(tmp_path: Path):
    binary = fake_binary(tmp_path, 'cat >/dev/null; echo "ciphertext"\n')
    sops = Sops(binary=str(binary))
    with pytest.raises(ExternalToolError):
        sops.encrypt(
            b"key: value\n",
            filename_override=Path("secrets/x.yaml"),
            cwd=tmp_path / "missing-dir",
        )


def test_available_with_env_missing_path_key_ignores_process_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    fake_binary(tmp_path, "true\n")
    monkeypatch.setenv("PATH", f"{tmp_path}{os.pathsep}{os.environ.get('PATH', '')}")
    sops = Sops(env={"SOPS_AGE_KEY_FILE": "unused"})
    assert not sops.available()
    with pytest.raises(ExternalToolError):
        sops.decrypt(tmp_path / "x.yaml")
