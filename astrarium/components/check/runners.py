"""xray and haproxy runners for check."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


DEFAULT_HAPROXY_IMAGE = "docker.io/library/haproxy:{version}"
"""Image for `haproxy -c`, `{version}` becomes node's features.haproxy.version. Digest refs work unchanged."""

CONTAINER_ENGINES = ("podman", "docker")

XRAY_TIMEOUT = 120.0

HAPROXY_TIMEOUT = 600.0

PROBE_TIMEOUT = 30.0

OUTPUT_TAIL = 2000

_HAPROXY_VERSION = re.compile(r"HA-?Proxy version (?P<version>\d+\.\d+)")

CheckKind = Literal["xray", "haproxy"]

CheckStatus = Literal["passed", "failed", "skipped"]

HaproxyStep = Literal["skip", "fail", "run"]


def major_minor(version: str) -> str:
    return ".".join(version.strip().split(".")[:2])


@dataclass(frozen=True)
class CheckResult:
    """One test on one node, detail holds masked tool output or reason."""

    node_id: str
    kind: CheckKind
    status: CheckStatus
    detail: str = ""


def _run(argv: list[str], *, timeout: float, env: dict[str, str] | None = None) -> tuple[bool, str]:
    try:
        proc = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )  # noqa: S603
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()[-OUTPUT_TAIL:]


def run_xray_test(binary: Path, config: Path, asset_dir: Path) -> tuple[bool, str]:
    """`xray run -test` with geo assets from `asset_dir` -> (passed, output tail)."""

    env = {**os.environ, "XRAY_LOCATION_ASSET": str(asset_dir)}
    return _run(
        [
            str(binary),
            "run",
            "-test",
            "-config",
            str(config),
        ],
        timeout=XRAY_TIMEOUT,
        env=env,
    )


def haproxy_step(installed: bool, wanted: bool) -> HaproxyStep:
    """HAProxy gate for tests: nothing to test without install, failure when config needs missing HAProxy."""

    if installed:
        return "run"
    return "fail" if wanted else "skip"


@dataclass(frozen=True)
class HaproxyChecker:
    """`haproxy -c` through local binary or container engine."""

    prefix: tuple[str, ...]

    container: bool

    image_template: str = DEFAULT_HAPROXY_IMAGE

    def check(self, cfg: Path, workdir: Path, version: str) -> tuple[bool, str]:
        return _run(
            self.argv(
                cfg,
                workdir,
                version,
            ),
            timeout=HAPROXY_TIMEOUT,
        )

    def argv(self, cfg: Path, workdir: Path, version: str) -> list[str]:
        """Command checking `cfg`, container mounts `workdir` read-only at same path."""

        if not self.container:
            return [
                *self.prefix,
                "-c",
                "-f",
                str(cfg),
            ]
        image = self.image_template.replace("{version}", version)
        return [
            *self.prefix,
            "-v",
            f"{workdir}:{workdir}:ro",
            image,
            "-c",
            "-f",
            str(cfg),
        ]


def container_haproxy(image_template: str, which: Callable[[str], str | None] = shutil.which) -> HaproxyChecker | None:
    """Checker through podman, else docker, else None."""

    for engine in CONTAINER_ENGINES:
        if path := which(engine):
            # root inside container: rootless podman maps it to invoking user, who owns 0700 runtime dir
            prefix = (
                path,
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0",
                "--entrypoint",
                "haproxy",
            )
            return HaproxyChecker(
                prefix=prefix,
                container=True,
                image_template=image_template,
            )
    return None


def pick_haproxy(
    explicit: Path | None,
    image_template: str,
    which: Callable[[str], str | None] = shutil.which,
) -> HaproxyChecker | None:
    """Explicit binary, else haproxy on PATH, else podman, else docker, else None."""

    if explicit is not None:
        return HaproxyChecker(prefix=(str(explicit),), container=False)
    if local := which("haproxy"):
        return HaproxyChecker(prefix=(local,), container=False)
    return container_haproxy(image_template, which)


def haproxy_version(binary: str) -> str | None:
    """major.minor printed by `haproxy -v`, None when it prints none."""

    _, output = _run([binary, "-v"], timeout=PROBE_TIMEOUT)
    match = _HAPROXY_VERSION.search(output)
    return match["version"] if match else None


@dataclass(frozen=True)
class HaproxyTools:
    """Preferred checker, major.minor of local binary, container fallback for other node versions."""

    preferred: HaproxyChecker | None
    local_version: str | None = None
    fallback: HaproxyChecker | None = None

    def checker(self, version: str) -> tuple[HaproxyChecker | None, bool]:
        """Checker for node haproxy `version`, flag set when local binary runs other or unknown major.minor."""

        preferred = self.preferred
        if preferred is None or preferred.container or self.local_version == major_minor(version):
            return preferred, False
        if self.fallback is not None:
            return self.fallback, False
        return preferred, True


def haproxy_tools(
    explicit: Path | None,
    image_template: str,
    which: Callable[[str], str | None] = shutil.which,
) -> HaproxyTools:
    """pick_haproxy plus one `haproxy -v` probe of local binary, container fallback unless binary is explicit."""

    preferred = pick_haproxy(
        explicit,
        image_template,
        which,
    )
    if preferred is None or preferred.container:
        return HaproxyTools(preferred)
    fallback = None if explicit is not None else container_haproxy(image_template, which)
    return HaproxyTools(
        preferred,
        haproxy_version(preferred.prefix[0]),
        fallback,
    )
