"""sops stand-in for component tests: keeps keys readable, encodes leaf values, adds `sops` metadata."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import yaml

from astrarium.components.secrets.recipients import SopsConfig
from astrarium.components.secrets.sops import Sops
from astrarium.errors import ExternalToolError


PREFIX = "ENC[FAKE,data:"

SUFFIX = "]"


def _encode(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _encode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_encode(item) for item in value]
    return PREFIX + base64.b64encode(json.dumps(value).encode()).decode() + SUFFIX


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _decode(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode(item) for item in value]
    if isinstance(value, str) and value.startswith(PREFIX) and value.endswith(SUFFIX):
        return json.loads(base64.b64decode(value[len(PREFIX) : -len(SUFFIX)]))
    raise ExternalToolError("fake sops: value is not encrypted")


def _find_sops_yaml(path: Path) -> Path | None:
    """Nearest ancestor `.sops.yaml` above `path`, mirrors how sops itself locates its config."""

    for parent in path.resolve().parents:
        candidate = parent / ".sops.yaml"
        if candidate.is_file():
            return candidate
    return None


class FakeSops(Sops):
    """In-process Sops: `encrypt` output is sops-shaped YAML, `decrypt` reverses it, calls are recorded."""

    def available(self) -> bool:
        return True

    def rotate(self, path: Path) -> None:
        self.calls.append(("rotate", str(path)))

    def __init__(self, recipients: list[str] | None = None) -> None:
        super().__init__(binary="fake-sops", env={})
        self.recipients = ["age1fake"] if recipients is None else recipients
        self.calls: list[tuple[str, str]] = []

    def encrypt(self, plaintext: bytes, *, filename_override: Path, cwd: Path) -> bytes:
        self.calls.append(("encrypt", str(filename_override)))
        data = yaml.safe_load(plaintext) or {}
        document = {**_encode(data), "sops": {"fake": True, "age": [{"recipient": r} for r in self.recipients]}}
        return yaml.safe_dump(document, sort_keys=False).encode()

    def decrypt(self, path: Path) -> bytes:
        self.calls.append(("decrypt", str(path)))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or "sops" not in data:
            raise ExternalToolError(f"sops decrypt failed: {path.name} has no sops metadata")
        body = {key: value for key, value in data.items() if key != "sops"}
        return yaml.safe_dump(_decode(body), sort_keys=False).encode()

    def updatekeys(self, path: Path) -> None:
        """Rewrite `path`'s own sops.age recipients from nearest .sops.yaml, as real sops does."""

        self.calls.append(("updatekeys", str(path)))
        config_path = _find_sops_yaml(path)
        if config_path is None:
            return
        recipients = SopsConfig(config_path).recipients()
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return
        data["sops"] = {"fake": True, "age": [{"recipient": r} for r in recipients]}
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def write_encrypted(sops: Sops, target: Path, data: dict[str, Any], repo_root: Path) -> Path:
    """Encrypt `data` as YAML to `target` inside repo at `repo_root`."""

    target.parent.mkdir(parents=True, exist_ok=True)
    plaintext = yaml.safe_dump(data, sort_keys=False).encode()
    target.write_bytes(
        sops.encrypt(
            plaintext,
            filename_override=target.relative_to(repo_root),
            cwd=repo_root,
        )
    )
    return target
