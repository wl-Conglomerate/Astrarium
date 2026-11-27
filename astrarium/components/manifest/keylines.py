"""OpenSSH authorized_keys line parsing shared by manifest validation and access data."""

from __future__ import annotations

from astrarium.errors import InvalidManifest


KEY_TYPES = frozenset(
    {
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    }
)


def _preview(line: str) -> str:
    return line.replace("\n", "\\n").replace("\r", "\\r")[:40]


def _options_end(text: str) -> int:
    quoted = False
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char in " \t" and not quoted:
            return index
    raise InvalidManifest(f"authorized key line has no key after its options: {_preview(text)}")


def split_key_line(line: str) -> tuple[str, str]:
    """Split authorized_keys line into (options, key), InvalidManifest when malformed or multi-line."""

    if "\n" in line or "\r" in line:
        raise InvalidManifest(f"authorized key line contains a line break: {_preview(line)}")
    text = line.strip()
    options, key = "", text
    first = text.split(maxsplit=1)[0] if text else ""
    if first not in KEY_TYPES:
        end = _options_end(text)
        options, key = text[:end], text[end:].strip()
    fields = key.split()
    if len(fields) < 2 or fields[0] not in KEY_TYPES:
        raise InvalidManifest(f"not an OpenSSH public key line: {_preview(line)}")
    return options, key


def split_options(options: str) -> list[str]:
    """Comma-separated options of authorized_keys line, commas inside quotes kept."""

    parts: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(options):
        if escaped:
            escaped = False
        elif char == "\\" and quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif char == "," and not quoted:
            parts.append(options[start:index])
            start = index + 1
    parts.append(options[start:])
    return [part for part in parts if part]


def key_identity(line: str) -> tuple[str, str] | None:
    """(key type, base64 blob) of line, options and comment left out, None for malformed line."""

    try:
        _, key = split_key_line(line)
    except InvalidManifest:
        # malformed line refused with its own message where access data is built
        return None
    key_type, blob = key.split()[:2]
    return key_type, blob
