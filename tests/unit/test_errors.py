"""Exit codes and sibling-tool message cleanup."""

import pytest

from astrarium.errors import (
    AstrariumError,
    ExitCode,
    ExternalToolError,
    InvalidManifest,
    PartialFailure,
    Refused,
    UsageProblem,
    strip_markup,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (AstrariumError, ExitCode.ERROR),
        (ExternalToolError, ExitCode.ERROR),
        (InvalidManifest, ExitCode.INVALID),
        (UsageProblem, ExitCode.INVALID),
        (PartialFailure, ExitCode.PARTIAL),
        (Refused, ExitCode.REFUSED),
    ],
)
def test_error_classes_carry_documented_exit_codes(error, code):
    assert error("boom").exit_code == code


def test_external_tool_errors_lose_rich_markup():
    e = ExternalToolError("[red][bold]Schema validation failed[/bold]:\n  [yellow]regions.0[/yellow]: bad[/red]")
    assert "[" not in e.message
    assert "Schema validation failed" in e.message
    assert "regions.0" in e.message


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "[red]host \\[2001:db8::1]:22[/red]",
            "host [2001:db8::1]:22",
            id="keeps-escaped-brackets",
        ),
        pytest.param(
            "[red bold]failed[/red bold]",
            "failed",
            id="removes-style-tags",
        ),
        pytest.param(
            "! [rejected] main -> main (fetch first)",
            "! [rejected] main -> main (fetch first)",
            id="keeps-non-style-brackets",
        ),
        pytest.param(
            "ssh: connect to host [fd00::1]:22 refused",
            "ssh: connect to host [fd00::1]:22 refused",
            id="keeps-ipv6-host-brackets",
        ),
        pytest.param(
            "\\[x]",
            "[x]",
            id="unescapes-literal-bracket",
        ),
    ],
)
def test_strip_markup(text: str, expected: str):
    assert strip_markup(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "[/] stray close",
            "stray close",
            id="removes-bare-closing-tag",
        ),
        pytest.param(
            "\\[red] literal in fallback [/]",
            "[red] literal in fallback",
            id="fallback-both-forms",
        ),
    ],
)
def test_strip_markup_keeps_content_around_alone_tags(text: str, expected: str):
    """Tag removal leaves surrounding spacing untouched, so only content presence is pinned."""

    result = strip_markup(text)
    assert expected in result
