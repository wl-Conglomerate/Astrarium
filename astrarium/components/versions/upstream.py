"""GitHub releases and commits client, fetched once per run and ETag-cached on disk."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx

from astrarium.errors import ExternalToolError


API = "https://api.github.com"

_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

logger = logging.getLogger(__name__)


class UpstreamNotFound(ExternalToolError):
    """GitHub answered 404 (unknown repo, tag, branch or commit)."""


@dataclass(frozen=True)
class Asset:
    name: str
    url: str
    digest: str | None
    """sha256 hex from API `digest` ("sha256:<hex>"), None when absent."""


@dataclass(frozen=True)
class Release:
    tag: str
    assets: dict[str, Asset]


def _release(data: dict[str, Any]) -> Release:
    assets = {}
    for item in data.get("assets", []):
        digest = item.get("digest")
        hexdigest = digest.removeprefix("sha256:") if isinstance(digest, str) and digest.startswith("sha256:") else None
        assets[item["name"]] = Asset(
            name=item["name"],
            url=item["browser_download_url"],
            digest=hexdigest,
        )
    return Release(tag=data["tag_name"], assets=assets)


class UpstreamClient:
    """GITHUB_TOKEN optional, sent to api.github.com only, never to downloads."""

    def release(self, repo: str, tag: str) -> Release:
        return _release(self._get(f"/repos/{repo}/releases/tags/{tag}"))

    def head_sha(self, repo: str, branch: str = "main") -> str:
        return str(self._get(f"/repos/{repo}/commits/{branch}")["sha"])

    def __init__(self, cache_dir: Path, token: str | None, client: httpx.Client | None = None) -> None:
        self._cache = cache_dir / "github"
        self._token = token
        self._client = client if client is not None else httpx.Client(timeout=30.0, follow_redirects=True)
        self._memo: dict[str, Any] = {}

    def latest(self, repo: str, *, pre: bool) -> Release:
        """Latest stable release, or newest non-draft release (prereleases included) with pre."""

        if not pre:
            return _release(self._get(f"/repos/{repo}/releases/latest"))
        for item in self._get(f"/repos/{repo}/releases", {"per_page": "30"}):
            if not item.get("draft", False):
                return _release(item)
        raise UpstreamNotFound(f"{repo} has no releases")

    def is_reachable(self, repo: str, sha: str, branch: str = "main") -> bool:
        """True when sha is on branch: compare sha...branch is "ahead" or "identical"."""

        try:
            body = self._get(f"/repos/{repo}/compare/{sha}...{branch}", {"per_page": "1"})
        except UpstreamNotFound:
            return False
        return body.get("status") in ("ahead", "identical")

    def download(self, url: str, dest: Path) -> Path:
        """Stream url to dest atomically (redirects followed, no token sent)."""

        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(f"{dest.name}.part")
        try:
            with self._client.stream(
                "GET",
                url,
                follow_redirects=True,
            ) as response:
                if response.status_code != 200:
                    raise ExternalToolError(f"download of {url} failed: HTTP {response.status_code}")
                with part.open("wb") as handle:
                    for chunk in response.iter_bytes():
                        handle.write(chunk)
        except ExternalToolError:
            raise
        except (httpx.HTTPError, OSError) as e:
            part.unlink(missing_ok=True)
            self._log_dropped(f"download of {url} failed", e)
            raise ExternalToolError(f"download of {url} failed: {type(e).__name__}") from e
        part.replace(dest)
        return dest

    def _get(self, path: str, params: dict[str, str] | None = None) -> Any:
        key = path + (f"?{urlencode(sorted(params.items()))}" if params else "")
        if key in self._memo:
            return self._memo[key]
        cache_file = self._cache / f"{hashlib.sha256(key.encode()).hexdigest()}.json"
        cached = self._read_cache(cache_file)
        headers = dict(_HEADERS)
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        if cached is not None:
            headers["If-None-Match"] = cached["etag"]
        try:
            response = self._client.get(
                f"{API}{path}",
                params=params,
                headers=headers,
            )
        except httpx.HTTPError as e:
            self._log_dropped(f"GitHub API request {path} failed", e)
            raise ExternalToolError(f"GitHub API request {path} failed: {type(e).__name__}") from e
        if response.status_code == 304 and cached is not None:
            body = cached["body"]
        elif response.status_code == 200:
            try:
                body = response.json()
            except ValueError as e:
                self._log_dropped(f"GitHub API {path} returned invalid JSON", e)
                raise ExternalToolError(f"GitHub API {path} returned invalid JSON") from e
            if etag := response.headers.get("etag"):
                self._write_cache(cache_file, {"etag": etag, "body": body})
        elif response.status_code == 404:
            raise UpstreamNotFound(f"GitHub: {path} not found")
        elif response.status_code in (403, 429) and response.headers.get("x-ratelimit-remaining") == "0":
            raise ExternalToolError(
                "GitHub API rate limit reached",
                hint="set GITHUB_TOKEN (unauthenticated limit is 60 requests per hour)",
            )
        else:
            raise ExternalToolError(f"GitHub API {path} returned HTTP {response.status_code}")
        self._memo[key] = body
        return body

    def _log_dropped(self, message: str, exc: Exception) -> None:
        """Warn with exc detail, token masked, since raised ExternalToolError keeps only exc type name."""

        detail = str(exc).replace(self._token, "***") if self._token else str(exc)
        logger.warning(
            f"{message}: {detail}",
        )

    @staticmethod
    def _read_cache(path: Path) -> dict[str, Any] | None:
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) and "etag" in data and "body" in data else None

    @staticmethod
    def _write_cache(path: Path, data: dict[str, Any]) -> None:
        """Best-effort, swallows OSError so cache failure never aborts request."""

        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(data))
            tmp.replace(path)
        except OSError as e:
            logger.debug(
                f"failed to write upstream cache {path}: {e}",
            )
