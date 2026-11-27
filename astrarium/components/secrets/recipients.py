""".sops.yaml recipient edits."""

from __future__ import annotations

import io
import re
from collections.abc import Iterable
from pathlib import Path

from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap, CommentedSeq

from astrarium.errors import InvalidManifest, UsageProblem


AGE_RECIPIENT = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")

SSH_RECIPIENT = re.compile(r"^ssh-ed25519 [A-Za-z0-9+/]+={0,2}( [^\s,][^\n,]*)?$")


def recipient_identity(recipient: str) -> str:
    return " ".join(recipient.split()[:2]) if recipient.startswith("ssh-") else recipient


def normalize_recipient(value: str) -> str:
    """Recipient as written to .sops.yaml: native age key or `ssh-ed25519` public key line.

    Invalid input is never echoed: it may be private key pasted by mistake.
    """

    text = value.strip()
    if text.upper().startswith("AGE-SECRET-KEY-") or "PRIVATE KEY" in text.upper():
        raise UsageProblem(
            "refusing private key given as recipient (value not shown)",
            hint="pass public side: age1... (`age-keygen -y KEYFILE`) or ssh-ed25519 line of .pub file",
        )
    if AGE_RECIPIENT.fullmatch(text) or SSH_RECIPIENT.fullmatch(text):
        return text
    raise UsageProblem(
        "not an age or ssh-ed25519 recipient (value not shown)", hint="use age1... or `ssh-ed25519 AAAA... comment`"
    )


def _split(value: object) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, list):
        return [str(part).strip() for part in value]
    return []


class SopsConfig:
    """`.sops.yaml` creation rules edited with ruamel round trip."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._yaml = YAML(typ="rt")
        self._yaml.preserve_quotes = True
        self._yaml.width = 4096
        try:
            self.data = self._yaml.load(path.read_text(encoding="utf-8"))
        except FileNotFoundError as e:
            raise InvalidManifest(f"{path.name} not found") from e
        rules = self.data.get("creation_rules") if isinstance(self.data, CommentedMap) else None
        if not isinstance(rules, CommentedSeq) or not rules:
            raise InvalidManifest(f"{path.name}: no creation_rules")
        if any("key_groups" in rule for rule in rules):
            raise UsageProblem(f"{path.name} uses key_groups: edit recipients by hand, then run `sops updatekeys`")
        self.rules: CommentedSeq = rules

    def recipients(self) -> list[str]:
        """Recipients of every creation rule, first occurrence order."""

        seen: list[str] = []
        for rule in self.rules:
            for recipient in _split(rule.get("age")):
                if recipient not in seen:
                    seen.append(recipient)
        return seen

    def update(self, *, add: Iterable[str] = (), remove: Iterable[str] = (), missing_ok: bool = False) -> list[str]:
        """Add/remove recipients in `age` of every rule, keeping string or list form, return new list.

        Removing recipient not in file is UsageProblem unless `missing_ok`.
        """

        added = [normalize_recipient(value) for value in add]
        removed = {recipient_identity(normalize_recipient(value)) for value in remove}
        known = {recipient_identity(recipient) for recipient in self.recipients()}
        absent = sorted(removed - known)
        if absent and not missing_ok:
            raise UsageProblem(f"not a recipient: {', '.join(absent)}")
        for rule in self.rules:
            original = _split(rule.get("age"))
            current = [r for r in original if recipient_identity(r) not in removed]
            current += [r for r in added if recipient_identity(r) not in {recipient_identity(c) for c in current}]
            if not current:
                if original:
                    raise UsageProblem("removing every recipient would make secrets undecryptable")
                # rule without age recipients (pgp-only) stays untouched
                continue
            rule["age"] = CommentedSeq(current) if isinstance(rule.get("age"), list) else ",".join(current)
        return self.recipients()

    def save(self) -> None:
        buffer = io.StringIO()
        self._yaml.dump(self.data, buffer)
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        tmp.write_text(buffer.getvalue(), encoding="utf-8")
        tmp.replace(self.path)
