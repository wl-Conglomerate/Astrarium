"""Geo data: same URLs as NullForge, verified, cached per release."""

from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path

import httpx
import pytest

from astrarium.components.check.geodata import GEOIP_DAT_URL, GEOSITE_DAT_URL, ensure_geodata
from astrarium.errors import ExternalToolError


pytestmark = pytest.mark.component

TAG = "202609250012"

PAYLOADS = {"geoip.dat": b"geoip-bytes", "geosite.dat": b"geosite-bytes"}


def _client(calls: list[tuple[str, str]], *, bad_sum: bool = False) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        name = request.url.path.rsplit("/", 1)[-1]
        if request.method == "HEAD":
            location = f"https://github.com/Loyalsoldier/v2ray-rules-dat/releases/download/{TAG}/{name}"
            return httpx.Response(302, headers={"location": location})
        if name.endswith(".sha256sum"):
            data = b"other" if bad_sum else PAYLOADS[name.removesuffix(".sha256sum")]
            return httpx.Response(200, text=f"{hashlib.sha256(data).hexdigest()}  {name}\n")
        return httpx.Response(200, content=PAYLOADS[name])

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_geo_urls_match_nullforge_rune() -> None:
    spec = importlib.util.find_spec("nullforge")
    assert spec is not None
    assert spec.submodule_search_locations is not None
    source = Path(next(iter(spec.submodule_search_locations))) / "runes" / "xray.py"
    constants = {
        target.id: node.value.value
        for node in ast.parse(source.read_text()).body
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name)
    }

    assert constants["GEOIP_DAT_URL"] == GEOIP_DAT_URL
    assert constants["GEOSITE_DAT_URL"] == GEOSITE_DAT_URL


def test_ensure_geodata_downloads_release_once_and_prunes_older(tmp_path: Path) -> None:
    stale = tmp_path / "geodata" / "202601010000"
    stale.mkdir(parents=True)
    calls: list[tuple[str, str]] = []

    with _client(calls) as client:
        first = ensure_geodata(tmp_path, client).path
        downloads = [call for call in calls if call[0] == "GET"]
        second = ensure_geodata(tmp_path, client).path

    assert first == second == tmp_path / "geodata" / TAG
    assert (first / "geoip.dat").read_bytes() == PAYLOADS["geoip.dat"]
    assert (first / "geosite.dat").read_bytes() == PAYLOADS["geosite.dat"]
    assert [call for call in calls if call[0] == "GET"] == downloads
    assert all(f"/download/{TAG}/" in path for _, path in downloads)
    assert not stale.exists()


def test_ensure_geodata_rejects_checksum_mismatch(tmp_path: Path) -> None:
    with _client([], bad_sum=True) as client, pytest.raises(ExternalToolError):
        ensure_geodata(tmp_path, client)

    assert not list((tmp_path / "geodata").rglob("*.dat"))


def test_ensure_geodata_falls_back_to_newest_complete_cached_release_when_lookup_fails(tmp_path: Path) -> None:
    for tag, names in (
        ("202601010000", PAYLOADS),
        ("202605010000", PAYLOADS),
        ("202609010000", ["geoip.dat"]),
    ):
        release = tmp_path / "geodata" / tag
        release.mkdir(parents=True)
        for name in names:
            (release / name).write_bytes(b"cached")

    def offline(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    with httpx.Client(transport=httpx.MockTransport(offline)) as client:
        geo = ensure_geodata(tmp_path, client)

    assert geo.path == tmp_path / "geodata" / "202605010000"
    assert geo.warning is not None
