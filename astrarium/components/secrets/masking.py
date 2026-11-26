"""Masking before diffs, logs and notifications: structural by key and directive, then by known value."""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import sys
from collections.abc import Callable, Iterable, Iterator, Mapping
from typing import Any, ClassVar

from astrarium.components.manifest.layering import get_path, set_path


MASK = "***"

SECRET_JSON_KEYS: frozenset[str] = frozenset(
    {
        "id",
        "password",
        "privateKey",
        "publicKey",
        "shortIds",
        "decryption",
        "encryption",
        "seed",
        "psk",
        "auth",
        "secret",
        "token",
        "secretKey",
        "pass",
        "key",
    }
)
"""xray/HexRift JSON keys whose values are credentials or identities."""

_BASE64 = re.compile(r"^(?:[A-Za-z0-9+/]+|[A-Za-z0-9_-]+)={0,2}$")

_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")

_HAPROXY_SECRET = re.compile(
    r"(?im)^(\s*(?:stats\s+auth|(?:insecure-)?password|user\s+\S+\s+(?:insecure-)?password)\s+)(\S+)"
)

XRAY_AUTH_MODE_LITERALS: frozenset[str] = frozenset({"password", "noauth"})
"""xray socks/http inbound `settings.auth` mode selectors: plain English words, never credentials."""


def mask_haproxy(text: str) -> str:
    return _HAPROXY_SECRET.sub(lambda match: match.group(1) + MASK, text)


def haproxy_secret_values(text: str) -> Iterator[str]:
    return (match.group(2) for match in _HAPROXY_SECRET.finditer(text))


def ci_mask_hook() -> Callable[[str], None] | None:
    return _add_mask_lines if os.environ.get("GITHUB_ACTIONS") == "true" else None


def _add_mask_lines(value: str) -> None:
    """::add-mask::<line> to stderr per non-empty line of `value` at least ValueMasker.MIN_LENGTH long, `%` escaped."""

    for line in value.splitlines():
        if line.strip() and len(line) >= ValueMasker.MIN_LENGTH:
            sys.stderr.write(f"::add-mask::{line.replace('%', '%25')}\n")
    sys.stderr.flush()


def mask_structure(obj: Any) -> Any:
    """Copy of JSON-like `obj` with values under SECRET_JSON_KEYS replaced by MASK."""

    if isinstance(obj, Mapping):
        return {
            key: MASK
            if key in SECRET_JSON_KEYS
            and obj[key]
            not in (
                None,
                "",
                [],
                {},
            )
            else mask_structure(value)
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [mask_structure(item) for item in obj]
    return obj


def mask_paths(data: Mapping[str, Any], paths: Iterable[str]) -> dict[str, Any]:
    """Copy of `data` with non-empty values at dotted `paths` replaced by MASK."""

    masked = json.loads(json.dumps(data))
    for path in paths:
        try:
            value = get_path(masked, path)
        except KeyError:
            continue
        if value not in (
            None,
            "",
            [],
            {},
        ):
            set_path(
                masked,
                path,
                MASK,
            )
    return masked


def _base64_forms(data: bytes) -> set[str]:
    standard = base64.b64encode(data).decode()
    urlsafe = base64.urlsafe_b64encode(data).decode()
    return {
        standard,
        standard.rstrip("="),
        urlsafe,
        urlsafe.rstrip("="),
    }


def _base64_decoded(value: str) -> bytes | None:
    if not _BASE64.fullmatch(value):
        return None
    body = value.rstrip("=").translate(_URLSAFE_TO_STANDARD)
    if len(body) % 4 == 1:
        return None
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except binascii.Error:
        return None


def secret_leaves(data: Any) -> Iterable[str]:
    """Every scalar leaf of nested dicts/lists as string."""

    if isinstance(data, Mapping):
        for value in data.values():
            yield from secret_leaves(value)
    elif isinstance(data, list):
        for item in data:
            yield from secret_leaves(item)
    elif data is not None and not isinstance(data, bool):
        yield str(data)


def secret_json_leaves(data: Any) -> Iterator[str]:
    """Leaf string values nested anywhere under SECRET_JSON_KEYS key of JSON-like `data`.

    For rendered xray/HAProxy configs: catches derived secrets (Hysteria obfs password,
    self-signed cert private key) never appearing in decrypted overlay/key files, so
    free-text output (xray -test, payload logs) still needs them registered for masking.

    Skips `auth` itself when its value is xray mode literal (XRAY_AUTH_MODE_LITERALS): plain
    word "password"/"noauth" selecting inbound's auth mode, not credential.
    """

    if isinstance(data, Mapping):
        for key, value in data.items():
            if key == "auth" and value in XRAY_AUTH_MODE_LITERALS:
                continue
            if key in SECRET_JSON_KEYS:
                yield from secret_leaves(value)
            else:
                yield from secret_json_leaves(value)
    elif isinstance(data, list):
        for item in data:
            yield from secret_json_leaves(item)


class ValueMasker:
    """Masks known secret values in text: raw, JSON-escaped and base64 forms.

    Base64 forms cover standard and urlsafe alphabet, padded and unpadded, of value itself and,
    when value is base64, of its decoded bytes (key stored urlsafe, rendered standard).
    """

    MIN_LENGTH: ClassVar[int] = 8

    def __init__(self, on_add: Callable[[str], None] | None = None) -> None:
        self._forms: set[str] = set()
        self._pattern: re.Pattern[str] | None = None
        self._on_add = on_add

    def add(self, value: str) -> None:
        """Register one secret, its derived re-encodings, and, for values spanning several lines
        (e.g. PEM rendered as one string), each of its own non-blank lines too, so lone lines found
        in free text still mask. Values (and lines) shorter than MIN_LENGTH ignored.

        `on_add` (if given to constructor) fires once per newly registered form, including every
        derived re-encoding, but not once more per individual multi-line split: caller already
        turning one notified value into per-line output (CLI add-mask hook) would otherwise see
        each real line twice, once from splitting whole value, once from line's own notification.
        """

        if len(value) < self.MIN_LENGTH:
            return
        forms = {
            value,
            json.dumps(value)[1:-1],
            *_base64_forms(value.encode()),
        }
        decoded = _base64_decoded(value)
        if decoded is not None:
            forms |= _base64_forms(decoded)
        forms = {form for form in forms if len(form) >= self.MIN_LENGTH}
        lines = value.splitlines()
        line_forms = (
            {line for line in lines if line.strip() and len(line) >= self.MIN_LENGTH} if len(lines) > 1 else set()
        )
        new = (forms | line_forms) - self._forms
        if not new:
            return
        self._forms |= new
        self._pattern = None
        if self._on_add is not None:
            for form in sorted(new - line_forms):
                self._on_add(form)

    def add_many(self, values: Iterable[str]) -> None:
        for value in values:
            self.add(value)

    def mask(self, text: str) -> str:
        """`text` with every registered form replaced by MASK, longest first."""

        if not self._forms:
            return text
        if self._pattern is None:
            self._pattern = re.compile(
                "|".join(
                    re.escape(form)
                    for form in sorted(
                        self._forms,
                        key=len,
                        reverse=True,
                    )
                )
            )
        return self._pattern.sub(MASK, text)
