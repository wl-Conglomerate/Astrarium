"""Encrypted HexRift key files under secrets/keys."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from astrarium.components.secrets.sops import Sops
from astrarium.repo import Repo


class KeyStore:
    """Encrypted key files of one repo: listing, decryption into runtime dir, atomic encrypted writes."""

    def __init__(self, repo: Repo, sops: Sops) -> None:
        self.repo = repo
        self.sops = sops

    def node_ids(self) -> set[str]:
        """Ids with key file in secrets/keys."""

        if not self.repo.keys_dir.is_dir():
            return set()
        return {path.stem for path in self.repo.keys_dir.glob("*.yaml") if path.is_file()}

    def missing(self, node_ids: Iterable[str]) -> list[str]:
        """Sorted ids of `node_ids` without key file."""

        present = self.node_ids()
        return sorted({node_id for node_id in node_ids if node_id not in present})

    def decrypt_all(self, dest: Path) -> Path:
        """Decrypt every key file to `<dest>/<id>.yaml` (0600), return `dest`."""

        dest.mkdir(
            mode=0o700,
            parents=True,
            exist_ok=True,
        )
        for node_id in sorted(self.node_ids()):
            plaintext = self.sops.decrypt(self.repo.key_file(node_id))
            target = dest / f"{node_id}.yaml"
            fd = os.open(
                target,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(fd, "wb") as handle:
                handle.write(plaintext)
        return dest

    def store(self, node_id: str, plaintext_file: Path) -> None:
        """Encrypt `plaintext_file` for `secrets/keys/<id>.yaml` and replace that file atomically."""

        target = self.repo.key_file(node_id)
        ciphertext = self.sops.encrypt(
            plaintext_file.read_bytes(),
            filename_override=target.relative_to(self.repo.root),
            cwd=self.repo.root,
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(
            dir=target.parent,
            prefix=f".{target.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(ciphertext)
            Path(tmp).chmod(0o644)
            Path(tmp).replace(target)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
