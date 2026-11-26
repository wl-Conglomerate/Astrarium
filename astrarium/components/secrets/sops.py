"""sops wrapper: decrypt, encrypt from stdin, updatekeys, rotate."""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping
from pathlib import Path

import yaml

from astrarium.errors import ExternalToolError


SOPS_HINT = "check `sops --version` (>= 3.10) and that your age identity is a recipient in .sops.yaml"


def _last_line(stderr: bytes) -> str:
    lines = [line.strip() for line in stderr.decode(errors="replace").splitlines() if line.strip()]
    return lines[-1] if lines else "no error output"


class Sops:
    """Runs sops binary, failures raise ExternalToolError without echoing stdin or plaintext."""

    def available(self) -> bool:
        return shutil.which(self.binary, path=self.env.get("PATH", os.defpath)) is not None

    def decrypt(self, path: Path) -> bytes:
        return self._run(["decrypt", str(path.resolve())], cwd=path.resolve().parent)

    def encrypt(self, plaintext: bytes, *, filename_override: Path, cwd: Path) -> bytes:
        return self._run(
            [
                "encrypt",
                "--filename-override",
                str(filename_override),
            ],
            cwd=cwd,
            stdin=plaintext,
            show_stderr=False,
        )

    def updatekeys(self, path: Path) -> None:
        self._run(
            [
                "updatekeys",
                "-y",
                str(path.resolve()),
            ],
            cwd=path.resolve().parent,
        )

    def rotate(self, path: Path) -> None:
        self._run(
            [
                "rotate",
                "-i",
                str(path.resolve()),
            ],
            cwd=path.resolve().parent,
        )

    def __init__(self, binary: str = "sops", env: Mapping[str, str] | None = None) -> None:
        self.binary = binary
        self.env = dict(os.environ if env is None else env)

    def _run(self, args: list[str], *, cwd: Path, stdin: bytes | None = None, show_stderr: bool = True) -> bytes:
        if not self.available():
            raise ExternalToolError(
                f"{self.binary} not found on PATH", hint="install sops >= 3.10 (https://getsops.io)"
            )
        try:
            proc = subprocess.run(  # noqa: S603
                [self.binary, *args],
                input=stdin,
                capture_output=True,
                cwd=cwd,
                env=self.env,
                check=False,
            )
        except OSError as e:
            raise ExternalToolError(f"sops {args[0]} could not run: {e}", hint=SOPS_HINT) from e
        if proc.returncode != 0:
            detail = _last_line(proc.stderr) if show_stderr else "stderr withheld (may contain plaintext)"
            raise ExternalToolError(f"sops {args[0]} failed (exit {proc.returncode}): {detail}", hint=SOPS_HINT)
        return proc.stdout

    @staticmethod
    def has_metadata(path: Path) -> bool:
        """File is YAML with top-level `sops` mapping (sops-encrypted)."""

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (
            OSError,
            UnicodeDecodeError,
            yaml.YAMLError,
        ):
            return False
        return isinstance(data, dict) and isinstance(data.get("sops"), dict)

    @staticmethod
    def file_recipients(path: Path) -> list[str]:
        """Recipients of `path`'s own sops metadata (`sops.age[].recipient`), empty when unreadable."""

        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (
            OSError,
            UnicodeDecodeError,
            yaml.YAMLError,
        ):
            return []
        sops_meta = data.get("sops") if isinstance(data, dict) else None
        age = sops_meta.get("age") if isinstance(sops_meta, dict) else None
        if not isinstance(age, list):
            return []
        recipients = (entry.get("recipient") for entry in age if isinstance(entry, dict))
        return [recipient for recipient in recipients if isinstance(recipient, str)]
