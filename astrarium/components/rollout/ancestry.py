"""Local git facts for deploy: deploying commit and ancestry of recorded commits."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Iterable
from pathlib import Path

from astrarium.errors import UsageProblem
from astrarium.repo import Repo


_SHA = re.compile(r"[0-9a-f]{40}")


def descends_from(root: Path, recorded: str, commit: str) -> bool | None:
    return descends_from_many(
        root,
        [recorded],
        commit,
    ).get(recorded)


def head_commit_of(root: Path) -> str:
    """Full sha of HEAD in deployment repo."""

    sha = Repo(root).commit()
    if sha is None:
        raise UsageProblem("deployment repo has no commit to deploy", hint="commit astrarium.yaml first")
    return sha


def descends_from_many(root: Path, recorded: Iterable[str], commit: str) -> dict[str, bool | None]:
    """descends_from per recorded sha, batched: one `git rev-list` plus one `git cat-file --batch-check`."""

    wanted = list(dict.fromkeys(recorded))
    ancestors = {
        line
        for line in subprocess.run(  # noqa: S603
            [  # noqa: S607
                "git",
                "rev-list",
                commit,
            ],  # noqa: S607
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
    }
    known_proc = subprocess.run(  # noqa: S603
        [  # noqa: S607
            "git",
            "cat-file",
            "--batch-check=%(objectname) %(objecttype)",
        ],  # noqa: S607
        cwd=root,
        input="\n".join(wanted) + ("\n" if wanted else ""),
        capture_output=True,
        text=True,
        check=False,
    )
    known = {line.split()[0] for line in known_proc.stdout.splitlines() if line.split()[1:] == ["commit"]}
    return {sha: (None if _SHA.fullmatch(sha) is None or sha not in known else sha in ancestors) for sha in wanted}
