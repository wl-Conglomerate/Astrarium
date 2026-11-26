"""In-memory UpstreamClient stand-in, downloads served from dict."""

from __future__ import annotations

from pathlib import Path


class FakeUpstream:
    """Serves `download` from url -> bytes dict and records requested urls."""

    def __init__(self, files: dict[str, bytes] | None = None) -> None:
        self.files = files if files is not None else {}
        self.downloads: list[str] = []

    def download(self, url: str, dest: Path) -> Path:
        """Write stored bytes of url to dest."""

        self.downloads.append(url)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.files[url])
        return dest
