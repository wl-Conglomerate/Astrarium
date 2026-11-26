"""Typed errors and exit codes."""

from __future__ import annotations

import re
from enum import IntEnum
from typing import ClassVar

from rich.errors import StyleSyntaxError
from rich.markup import escape
from rich.style import Style


# Escaped open bracket ('\[', kept as literal '[') or bracket group
# ('[body]' / '[/body]'), tag candidate either way. Candidate vs real style
# tag decided in strip_markup below, not here, so sibling-tool text that
# merely looks bracketed (e.g. '[rejected]') stays for caller to judge.
_BRACKET = re.compile(r"\\\[|\[(/?)([^\[\]]*)\]")


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    INVALID = 2
    PARTIAL = 3
    REFUSED = 4


def _is_style_body(body: str) -> bool:
    """True when non-empty body parses as rich style, e.g. 'red' or 'bold red'."""

    try:
        Style.parse(body)
    except StyleSyntaxError:
        return False
    return True


def strip_markup(text: str) -> str:
    """Plain text of sibling-tool error carrying rich markup like `[red]...[/red]`.

    Removes only real rich style tags: opening tag whose body parses with
    `Style.parse` (`[red]`, `[bold red]`), closing tag for such style
    (`[/red]`), and bare closing tag `[/]`. Every other bracketed text,
    e.g. git's `[rejected]` or IPv6 host like `[fd00::1]:22`, kept verbatim.
    Escaped `\\[` becomes literal `[`.
    """

    def _replace(match: re.Match[str]) -> str:
        if match.group(0) == "\\[":
            return "["
        closing, body = match.group(1), match.group(2)
        if not body:
            return "" if closing else match.group(0)
        return "" if _is_style_body(body) else match.group(0)

    return _BRACKET.sub(_replace, text)


class AstrariumError(Exception):
    """Base error: message, optional fix hint, exit code per class."""

    exit_code: ClassVar[ExitCode] = ExitCode.ERROR

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def __rich__(self) -> str:
        text = f"[red bold]Error:[/] {escape(self.message)}"
        if self.hint:
            text += f"\n[dim]{escape(self.hint)}[/]"
        return text


class InvalidManifest(AstrariumError):
    """Manifest, overlay or topology content invalid (exit 2)."""

    exit_code = ExitCode.INVALID


class UsageProblem(AstrariumError):
    """Invalid command usage (exit 2)."""

    exit_code = ExitCode.INVALID


class Refused(AstrariumError):
    """Safety check refused operation (exit 4)."""

    exit_code = ExitCode.REFUSED


class Declined(AstrariumError):
    """Operator answered no at confirmation (exit 1)."""

    exit_code = ExitCode.ERROR


class PartialFailure(AstrariumError):
    """Some nodes failed, were not attempted or mismatched (exit 3)."""

    exit_code = ExitCode.PARTIAL


class ExternalToolError(AstrariumError):
    """sops, git, HexRift or NullForge failure (exit 1), rich markup stripped from message."""

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(strip_markup(message), hint=hint)
