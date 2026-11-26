"""xray binaries for deploy: verified release downloads or CI-built main@sha artifacts."""

from __future__ import annotations

import hashlib
import logging
import re
import zipfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast, get_args

from astrarium.components.manifest.models import Arch, VersionPin, XrayRelease
from astrarium.components.versions.upstream import UpstreamClient
from astrarium.errors import ExternalToolError, InvalidManifest, Refused, UsageProblem
from astrarium.runtime import RuntimeDir


LOG = logging.getLogger(__name__)

XRAY_REPO = "XTLS/Xray-core"

XRAY_ASSETS: Mapping[Arch, str] = MappingProxyType(
    {"x86_64": "Xray-linux-64.zip", "aarch64": "Xray-linux-arm64-v8a.zip"}
)

GOARCH: Mapping[Arch, str] = MappingProxyType({"x86_64": "amd64", "aarch64": "arm64"})
"""Manifest arch -> Go GOARCH, shared with CI build matrices (check component)."""

HEAD_PIN = re.compile(r"main@([0-9a-f]{40})")


def pin_label(pin: VersionPin) -> str:
    return pin.version if isinstance(pin, XrayRelease) else pin


@dataclass(frozen=True)
class XrayArtifact:
    arch: Arch
    binary: Path
    sha256: str
    label: str
    """Release tag or main@<sha> pin."""


def head_commit(pin: VersionPin) -> str | None:
    """Commit of main@<sha> pin, None for release pin, InvalidManifest for any other string."""

    if isinstance(pin, XrayRelease):
        return None
    match = HEAD_PIN.fullmatch(pin)
    if match is None:
        raise InvalidManifest(f"xray pin {pin!r} is neither a release nor main@<40-hex sha>")
    return match.group(1)


def sha256_file(path: Path) -> str:
    """Hex sha256 of file, read in chunks."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_artifact_options(values: Iterable[str]) -> dict[Arch, Path]:
    """`--artifact ARCH=PATH` values -> existing files by architecture."""

    result: dict[Arch, Path] = {}
    for value in values:
        arch, sep, path = value.partition("=")
        if not sep or not path or arch not in get_args(Arch):
            raise UsageProblem(f"--artifact expects ARCH=PATH with ARCH one of {', '.join(get_args(Arch))}")
        binary = Path(path).expanduser()
        if not binary.is_file():
            raise UsageProblem(f"--artifact {arch}: {binary} is not a file")
        result[cast(Arch, arch)] = binary.resolve()
    return result


class ArtifactResolver:
    """Resolves each (pin, arch) once per run, release zips cached under cache_dir/xray/<tag>/."""

    def __init__(self, upstream: UpstreamClient, cache_dir: Path, runtime: RuntimeDir) -> None:
        self._upstream = upstream
        self._cache_dir = cache_dir
        self._runtime = runtime
        self._resolved: dict[tuple[str, Arch], XrayArtifact] = {}

    def resolve(self, pin: VersionPin, arch: Arch, provided: Mapping[Arch, Path]) -> XrayArtifact:
        """Executable xray for pin and arch, Refused when main@sha lacks artifact or release hash differs."""

        key = (pin_label(pin), arch)
        if key not in self._resolved:
            if isinstance(pin, XrayRelease):
                self._resolved[key] = self._release(pin, arch)
            else:
                self._resolved[key] = self._head(
                    pin,
                    arch,
                    provided,
                )
        return self._resolved[key]

    def _head(self, pin: str, arch: Arch, provided: Mapping[Arch, Path]) -> XrayArtifact:
        head_commit(pin)
        binary = provided.get(arch)
        if binary is None:
            raise Refused(
                f"xray {pin} needs --artifact {arch}=PATH",
                hint="the CI build job compiles that exact commit per architecture",
            )
        return XrayArtifact(
            arch=arch,
            binary=binary,
            sha256=sha256_file(binary),
            label=pin,
        )

    def _release(self, pin: XrayRelease, arch: Arch) -> XrayArtifact:
        expected = pin.sha256.get(arch)
        if expected is None:
            raise Refused(
                f"xray {pin.version} has no sha256 for {arch} in astrarium.yaml",
                hint=f"run: arium versions bump xray {pin.version}",
            )
        asset = XRAY_ASSETS[arch]
        archive = self._cache_dir / "xray" / pin.version / asset
        if not archive.is_file() or sha256_file(archive) != expected:
            url = f"https://github.com/{XRAY_REPO}/releases/download/{pin.version}/{asset}"
            self._upstream.download(url, archive)
            if sha256_file(archive) != expected:
                archive.unlink()
                raise Refused(f"{asset} of xray {pin.version} does not match the sha256 in astrarium.yaml")
        try:
            with zipfile.ZipFile(archive) as bundle:
                data = bundle.read("xray")
        except (KeyError, zipfile.BadZipFile) as e:
            LOG.warning(
                f"{asset} of xray {pin.version} holds no xray binary: {e}",
            )
            raise ExternalToolError(f"{asset} of xray {pin.version} holds no xray binary") from e
        binary = self._runtime.sub(f"xray-{arch}-{pin.version}") / "xray"
        binary.write_bytes(data)
        binary.chmod(0o755)
        return XrayArtifact(
            arch=arch,
            binary=binary,
            sha256=hashlib.sha256(data).hexdigest(),
            label=pin.version,
        )
