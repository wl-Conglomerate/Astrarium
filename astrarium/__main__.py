"""Console entry point."""

from __future__ import annotations

import logging

import rich_click as click
from rich.markup import escape

from astrarium.app import cli
from astrarium.core import err
from astrarium.errors import AstrariumError, ExitCode


INTERRUPTED = 130


def main(argv: list[str] | None = None) -> None:
    """Run `astrarium`/`arium`, exit with mapped error code."""

    try:
        rv = cli.main(args=argv, standalone_mode=False)
    except AstrariumError as e:
        err.print(e)
        raise SystemExit(int(e.exit_code)) from None
    except click.ClickException as e:
        e.show()
        raise SystemExit(e.exit_code) from None
    except click.Abort:
        err.print("[yellow]Aborted.[/]")
        raise SystemExit(INTERRUPTED) from None
    except KeyboardInterrupt:
        err.print("[yellow]Interrupted.[/]")
        raise SystemExit(INTERRUPTED) from None
    except Exception as e:
        detail = escape(str(e))
        label = f"{type(e).__name__}: {detail}" if detail else type(e).__name__
        err.print(f"[red bold]Unexpected error:[/] {label}")
        if logging.getLogger("astrarium").isEnabledFor(logging.DEBUG):
            err.print_exception()
        raise SystemExit(ExitCode.ERROR) from None
    # `rv` is `None` on normal return (cli's result_callback discards it) or int
    # code passed to `ctx.exit(n)`, never command's own return value (see
    # astrarium/app.py's `_discard_result`).
    raise SystemExit(rv if isinstance(rv, int) else ExitCode.OK)


if __name__ == "__main__":
    main()
