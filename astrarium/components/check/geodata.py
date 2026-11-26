"""Geo data for `xray run -test`: files NullForge installs, cached per upstream release."""

from __future__ import annotations

import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import httpx

from astrarium.errors import ExternalToolError


GEOIP_DAT_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"

GEOSITE_DAT_URL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

GEO_DATS = {"geoip.dat": GEOIP_DAT_URL, "geosite.dat": GEOSITE_DAT_URL}
"""Copied from nullforge/runes/xray.py (importing that rune runs deploy code), test keeps them equal."""

_RELEASE = re.compile(r"/releases/download/(?P<tag>[0-9A-Za-z][0-9A-Za-z._-]*)/")


def _complete(release: Path) -> bool:
    return all((release / name).is_file() for name in GEO_DATS)


def release_tag(client: httpx.Client, url: str) -> str:
    """Release tag behind GitHub `latest/download` redirect."""

    try:
        response = client.head(url, follow_redirects=False)
    except httpx.HTTPError as e:
        raise ExternalToolError(f"geo data release lookup failed: {e}") from e
    match = _RELEASE.search(response.headers.get("location", ""))
    if not response.is_redirect or match is None:
        raise ExternalToolError(f"cannot resolve geo data release from {url} (HTTP {response.status_code})")
    return match["tag"]


@dataclass(frozen=True)
class GeoData:
    """Dir holding geoip.dat and geosite.dat, warning set when it is cached fallback."""

    path: Path
    warning: str | None = None


def newest_cached(cache_dir: Path) -> Path | None:
    """Newest cached release holding both files (files land only after verification), None without one."""

    root = cache_dir / "geodata"
    releases = sorted(root.iterdir(), reverse=True) if root.is_dir() else []
    return next((release for release in releases if release.is_dir() and _complete(release)), None)


def ensure_geodata(cache_dir: Path, client: httpx.Client) -> GeoData:
    """Current release (older ones pruned), newest cached release with warning when upstream fails."""

    try:
        tag = release_tag(client, GEOIP_DAT_URL)
        dest = cache_dir / "geodata" / tag
        if not _complete(dest):
            dest.mkdir(parents=True, exist_ok=True)
            for name, url in GEO_DATS.items():
                _download_verified(
                    client,
                    url.replace("/latest/download/", f"/download/{tag}/"),
                    dest / name,
                )
    except ExternalToolError as e:
        cached = newest_cached(cache_dir)
        if cached is None:
            raise
        return GeoData(cached, f"{e.message}: xray -test uses cached geo data release {cached.name}")
    for stale in dest.parent.iterdir():
        if stale.is_dir() and stale != dest:
            shutil.rmtree(stale)
    return GeoData(dest)


def _download_verified(client: httpx.Client, url: str, target: Path) -> None:
    """Stream `url` to `target` via .partial, verify against its .sha256sum, else raise."""

    partial = target.with_name(f"{target.name}.partial")
    digest = hashlib.sha256()
    try:
        fields = client.get(f"{url}.sha256sum", follow_redirects=True).raise_for_status().text.split()
        with (
            client.stream(
                "GET",
                url,
                follow_redirects=True,
            ) as response,
            partial.open("wb") as out,
        ):
            response.raise_for_status()
            for chunk in response.iter_bytes():
                digest.update(chunk)
                out.write(chunk)
    except httpx.HTTPError as e:
        partial.unlink(missing_ok=True)
        raise ExternalToolError(f"geo data download failed: {e}") from e
    if not fields or digest.hexdigest() != fields[0]:
        partial.unlink()
        raise ExternalToolError(f"checksum mismatch for {url}")
    partial.replace(target)
