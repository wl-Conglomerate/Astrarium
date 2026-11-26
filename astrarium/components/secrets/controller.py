"""Recipient changes: .sops.yaml edit, rotation then updatekeys on removal."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from astrarium.components.secrets.recipients import SopsConfig, normalize_recipient, recipient_identity
from astrarium.components.secrets.sops import Sops
from astrarium.core import BaseController
from astrarium.errors import ExternalToolError, PartialFailure, Refused, UsageProblem


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp

ROTATE_REMINDER = (
    "git history keeps the old ciphertext: rotate the secret values themselves "
    "(telemt users, Nezha tokens, Discord webhook, exit keys)"
)

YAML_SUFFIXES = frozenset({".yaml", ".yml"})

PLACEHOLDER_NAME = ".gitkeep"


def is_encrypted(path: Path) -> bool:
    return path.suffix in YAML_SUFFIXES and Sops.has_metadata(path)


def _paths(paths: list[Path]) -> str:
    return ", ".join(str(path) for path in paths) if paths else "none"


def secret_files(secrets_dir: Path) -> list[Path]:
    """Every regular file under `secrets_dir` except `.gitkeep` placeholders, sorted."""

    if not secrets_dir.is_dir():
        return []
    return sorted(path for path in secrets_dir.rglob("*") if path.is_file() and path.name != PLACEHOLDER_NAME)


def _unknown_recipients(recipients: list[str], before: list[str], files: list[Path]) -> list[str]:
    """Identities of `recipients` missing from both `before` (.sops.yaml) and every file's own sops metadata."""

    known = {recipient_identity(recipient) for recipient in before}
    for path in files:
        known |= {recipient_identity(recipient) for recipient in Sops.file_recipients(path)}
    requested = {recipient_identity(normalize_recipient(value)) for value in recipients}
    return sorted(requested - known)


@dataclass(frozen=True)
class RecipientChange:
    recipients: list[str]
    updated: list[Path]
    rotated: list[Path]


class SecretsController(BaseController["AstrariumApp"]):
    """sops recipients of every file under secrets/."""

    def encrypted_files(self) -> list[Path]:
        """Every file under secrets/ (placeholders aside), Refused (exit 4) unless each is sops-encrypted YAML."""

        repo = self.app.repo
        files = secret_files(repo.secrets_dir)
        plain = [str(path.relative_to(repo.root)) for path in files if not is_encrypted(path)]
        if plain:
            raise Refused(
                f"not sops-encrypted YAML: {', '.join(plain)}",
                hint="every file under secrets/ must be .yaml/.yml encrypted with sops: encrypt or move it",
            )
        return files

    def add_recipients(self, recipients: list[str]) -> RecipientChange:
        """Add recipients to .sops.yaml, then `sops updatekeys` every file."""

        config = SopsConfig(self.app.repo.sops_config)
        result = config.update(add=recipients)
        files = self.encrypted_files()
        config.save()
        for path in files:
            self.app.sops.updatekeys(path)
        return RecipientChange(
            recipients=result,
            updated=files,
            rotated=[],
        )

    def remove_recipients(self, recipients: list[str]) -> RecipientChange:
        """Remove recipients, `sops rotate -i` then `sops updatekeys` every file (new data key first).

        Refuses (UsageProblem, exit 2) recipient absent from both .sops.yaml and every file's own
        sops metadata, changing nothing: likely typo, not real recipient to converge away. Otherwise
        convergent: recipient already absent from .sops.yaml but still present in some file's metadata
        still gets every file rotated and re-wrapped, so rerun after partial failure converges.
        Rotate runs first because updatekeys rewrites file's own recipient metadata from .sops.yaml:
        doing it last means file whose updatekeys never ran still names old recipient in its own
        metadata, so rerun's _unknown_recipients check still finds it there instead of refusing it
        as typo. .sops.yaml saved before loop, so mid-loop sops failure raises PartialFailure
        (exit 3) naming done and remaining files, with manual commands.
        """

        config = SopsConfig(self.app.repo.sops_config)
        before = config.recipients()
        files = self.encrypted_files()
        unknown = _unknown_recipients(
            recipients,
            before,
            files,
        )
        if unknown:
            raise UsageProblem(f"not a recipient in .sops.yaml or any file: {', '.join(unknown)}")
        result = config.update(remove=recipients, missing_ok=True)
        if result != before:
            config.save()
        done: list[Path] = []
        for index, path in enumerate(files):
            try:
                self.app.sops.rotate(path)
                self.app.sops.updatekeys(path)
            except ExternalToolError as e:
                remaining = files[index:]
                raise PartialFailure(
                    f".sops.yaml recipients already changed to {result}, but sops failed on {path}: "
                    f"{e.message} (done: {_paths(done)}; remaining: {_paths(remaining)})",
                    hint="finish the remaining files by hand: "
                    + "; ".join(f"sops rotate -i {file} && sops updatekeys -y {file}" for file in remaining),
                ) from e
            done.append(path)
        return RecipientChange(
            recipients=result,
            updated=files,
            rotated=files,
        )
