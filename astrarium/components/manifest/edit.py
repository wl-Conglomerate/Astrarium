"""Round-trip manifest edits that keep comments and layout."""

from __future__ import annotations

import io
import os
import re
import tempfile
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.comments import CommentedMap
from ruamel.yaml.error import YAMLError

from astrarium.components.manifest.loader import validation_lines
from astrarium.components.manifest.models import Manifest, VersionPin, XrayRelease
from astrarium.errors import InvalidManifest


_KEY_LINE = re.compile(r"^( *)[^\s#-][^:#]*:\s*(#.*)?$")

_ITEM_LINE = re.compile(r"^( *)- ")

_HEAD = re.compile(r"\A(?:[ \t]*(?:[#%][^\n]*)?\n)*---[ \t]*(?:#[^\n]*)?(?:\n|\Z)")
"""Blank, comment and directive lines up to document start marker `---` (ruamel drops them)."""


def sequence_offset(text: str) -> int:
    """Indent of `- ` items relative to their parent key, taken from first block sequence in `text`."""

    lines = text.splitlines()
    for index, line in enumerate(lines[1:], start=1):
        item = _ITEM_LINE.match(line)
        if item is None:
            continue
        previous = next(
            (
                lines[i]
                for i in range(
                    index - 1,
                    -1,
                    -1,
                )
                if lines[i].strip() and not lines[i].lstrip().startswith("#")
            ),
            "",
        )
        key = _KEY_LINE.match(previous)
        if key is not None:
            return max(len(item.group(1)) - len(key.group(1)), 0)
    return 2


def _yaml(offset: int) -> YAML:
    handler = YAML(typ="rt")
    handler.preserve_quotes = True
    handler.width = 4096
    handler.indent(
        mapping=2,
        sequence=offset + 2,
        offset=offset,
    )
    return handler


class ManifestEditor:
    """Edits astrarium.yaml in place with ruamel round trip: comments, quotes and list style kept."""

    def __init__(self, path: Path) -> None:
        self.path = path
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise InvalidManifest(f"{path} not found") from None
        except (OSError, UnicodeDecodeError) as e:
            raise InvalidManifest(f"{path}: cannot read ({type(e).__name__})") from None
        head = _HEAD.match(text)
        self._head = head.group(0) if head is not None else ""
        self._yaml = _yaml(sequence_offset(text))
        try:
            data = self._yaml.load(text[len(self._head) :])
        except YAMLError as e:
            mark = getattr(
                e,
                "problem_mark",
                None,
            )
            skipped = self._head.count("\n")
            where = "" if mark is None else f" at line {mark.line + 1 + skipped}, column {mark.column + 1}"
            raise InvalidManifest(f"{path}: invalid YAML{where}") from None
        if not isinstance(data, CommentedMap):
            raise InvalidManifest(f"{path}: top level must be a mapping")
        self.data: CommentedMap = data

    def _mapping(self, parent: CommentedMap, key: str) -> CommentedMap:
        if key not in parent or parent[key] is None:
            parent[key] = CommentedMap()
        child = parent[key]
        if not isinstance(child, CommentedMap):
            raise InvalidManifest(f"{self.path.name}: {key} must be a mapping")
        return child

    def set_version(self, component: str, pin: VersionPin, node: str | None = None) -> None:
        """Set `versions.<component>`, or `nodes.<node>.overrides.versions.<component>` with `node`."""

        if node is None:
            target = self._mapping(self.data, "versions")
        else:
            nodes = self.data.get("nodes")
            if not isinstance(nodes, CommentedMap) or node not in nodes:
                raise InvalidManifest(f"{self.path.name}: no node {node!r}")
            target = self._mapping(self._mapping(self._mapping(nodes, node), "overrides"), "versions")
        target[component] = self._pin_value(pin)

    @staticmethod
    def _pin_value(pin: VersionPin) -> Any:
        if isinstance(pin, XrayRelease):
            value = CommentedMap()
            value["version"] = pin.version
            value["sha256"] = CommentedMap(sorted(pin.sha256.items()))
            return value
        return pin

    def render(self) -> str:
        """Current document as YAML text."""

        buffer = io.StringIO()
        self._yaml.dump(self.data, buffer)
        return self._head + buffer.getvalue()

    def save(self) -> None:
        """Validate then atomically replace file, keeping its mode."""

        text = self.render()
        try:
            Manifest.model_validate(yaml.safe_load(text))
        except ValidationError as e:
            raise InvalidManifest(f"{self.path.name} after edit: " + "; ".join(validation_lines(e))) from None
        mode = self.path.stat().st_mode & 0o777
        fd, tmp = tempfile.mkstemp(
            dir=self.path.parent,
            prefix=f".{self.path.name}.",
            suffix=".tmp",
        )
        try:
            with os.fdopen(
                fd,
                "w",
                encoding="utf-8",
            ) as handle:
                handle.write(text)
            Path(tmp).chmod(mode)
            Path(tmp).replace(self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
