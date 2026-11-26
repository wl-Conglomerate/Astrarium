"""GitHub client against httpx MockTransport: digests, ETag cache, compare, downloads."""

import httpx
import pytest

from astrarium.components.versions.upstream import UpstreamClient
from astrarium.errors import ExternalToolError


pytestmark = pytest.mark.component

RELEASE = {
    "tag_name": "v26.3.27",
    "prerelease": False,
    "assets": [
        {
            "name": "Xray-linux-64.zip",
            "browser_download_url": "https://github.com/dl/64.zip",
            "digest": "sha256:" + "ab" * 32,
        },
        {"name": "old.zip", "browser_download_url": "https://github.com/dl/old.zip"},
    ],
}


class Api:
    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self))

    def __init__(self, responses: dict[str, httpx.Response]) -> None:
        self.responses = responses
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.responses[request.url.path]


def test_release_normalises_asset_digests(tmp_path) -> None:
    api = Api({"/repos/XTLS/Xray-core/releases/tags/v26.3.27": httpx.Response(200, json=RELEASE)})

    release = UpstreamClient(
        tmp_path,
        None,
        api.client(),
    ).release("XTLS/Xray-core", "v26.3.27")

    assert release.assets["Xray-linux-64.zip"].digest == "ab" * 32
    assert release.assets["old.zip"].digest is None


def test_metadata_is_fetched_once_per_run_and_revalidated_with_etag(tmp_path) -> None:
    path = "/repos/XTLS/Xray-core/releases/tags/v26.3.27"
    first = Api(
        {
            path: httpx.Response(
                200,
                json=RELEASE,
                headers={"ETag": '"v1"'},
            )
        }
    )
    client = UpstreamClient(
        tmp_path,
        None,
        first.client(),
    )
    client.release("XTLS/Xray-core", "v26.3.27")
    client.release("XTLS/Xray-core", "v26.3.27")

    second = Api({path: httpx.Response(304)})
    again = UpstreamClient(
        tmp_path,
        None,
        second.client(),
    ).release("XTLS/Xray-core", "v26.3.27")

    assert len(first.requests) == 1
    assert second.requests[0].headers["If-None-Match"] == '"v1"'
    assert again.tag == "v26.3.27"


@pytest.mark.parametrize(
    ("status", "reachable"),
    [
        ("ahead", True),
        ("identical", True),
        ("behind", False),
        ("diverged", False),
    ],
)
def test_reachability_from_compare_status(tmp_path, status: str, reachable: bool) -> None:
    api = Api({f"/repos/XTLS/Xray-core/compare/{'a' * 40}...main": httpx.Response(200, json={"status": status})})

    assert (
        UpstreamClient(
            tmp_path,
            None,
            api.client(),
        ).is_reachable("XTLS/Xray-core", "a" * 40)
        is reachable
    )


def test_unknown_commit_is_not_reachable(tmp_path) -> None:
    api = Api({f"/repos/XTLS/Xray-core/compare/{'b' * 40}...main": httpx.Response(404)})

    assert (
        UpstreamClient(
            tmp_path,
            None,
            api.client(),
        ).is_reachable("XTLS/Xray-core", "b" * 40)
        is False
    )


def test_latest_prerelease_skips_drafts(tmp_path) -> None:
    listing = [
        {
            **RELEASE,
            "tag_name": "v26.9.9",
            "draft": True,
            "prerelease": True,
        },
        {
            **RELEASE,
            "tag_name": "v26.9.8",
            "prerelease": True,
        },
    ]
    api = Api({"/repos/XTLS/Xray-core/releases": httpx.Response(200, json=listing)})

    latest = UpstreamClient(
        tmp_path,
        None,
        api.client(),
    ).latest("XTLS/Xray-core", pre=True)

    assert latest.tag == "v26.9.8"


def test_rate_limit_is_reported(tmp_path) -> None:
    api = Api({"/repos/XTLS/Xray-core/commits/main": httpx.Response(403, headers={"x-ratelimit-remaining": "0"})})

    with pytest.raises(ExternalToolError) as excinfo:
        UpstreamClient(
            tmp_path,
            None,
            api.client(),
        ).head_sha("XTLS/Xray-core")

    assert excinfo.value.hint


def test_non_json_response_body_raises_external_tool_error(tmp_path) -> None:
    api = Api({"/repos/XTLS/Xray-core/commits/main": httpx.Response(200, content=b"<html>not json</html>")})

    with pytest.raises(ExternalToolError):
        UpstreamClient(
            tmp_path,
            None,
            api.client(),
        ).head_sha("XTLS/Xray-core")


def test_download_404_leaves_no_dest_or_part_file(tmp_path) -> None:
    api = Api({"/dl/missing.zip": httpx.Response(404)})
    dest = tmp_path / "out" / "asset.zip"

    with pytest.raises(ExternalToolError):
        UpstreamClient(
            tmp_path,
            None,
            api.client(),
        ).download("https://github.com/dl/missing.zip", dest)

    assert not dest.exists()
    assert not dest.with_name(f"{dest.name}.part").exists()


def test_token_goes_to_api_only_and_download_follows_redirects(tmp_path) -> None:
    api = Api(
        {
            "/repos/XTLS/Xray-core/commits/main": httpx.Response(200, json={"sha": "c" * 40}),
            "/dl/64.zip": httpx.Response(302, headers={"Location": "https://objects.example.net/blob"}),
            "/blob": httpx.Response(200, content=b"zipbytes"),
        }
    )
    client = UpstreamClient(
        tmp_path / "cache",
        "secret-token",
        api.client(),
    )

    assert client.head_sha("XTLS/Xray-core") == "c" * 40
    dest = client.download("https://github.com/dl/64.zip", tmp_path / "out" / "64.zip")

    assert dest.read_bytes() == b"zipbytes"
    assert api.requests[0].headers["Authorization"] == "Bearer secret-token"
    assert all("Authorization" not in request.headers for request in api.requests[1:])
