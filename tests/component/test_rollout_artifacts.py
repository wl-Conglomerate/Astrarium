"""xray artifacts: verified release zips, CI-built main@sha binaries, --artifact parsing."""

import hashlib
import io
import zipfile
from typing import cast

import pytest

from astrarium.components.manifest.models import XrayRelease
from astrarium.components.rollout.artifacts import ArtifactResolver, head_commit, parse_artifact_options
from astrarium.components.versions.upstream import UpstreamClient
from astrarium.errors import InvalidManifest, Refused, UsageProblem
from astrarium.runtime import RuntimeDir
from tests.support.fake_upstream import FakeUpstream


pytestmark = pytest.mark.component

URL = "https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip"

HEAD = "main@" + "a" * 40


def resolver(upstream: FakeUpstream, cache, runtime) -> ArtifactResolver:
    return ArtifactResolver(
        cast(UpstreamClient, upstream),
        cache,
        runtime,
    )


def xray_zip(binary: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as bundle:
        bundle.writestr("xray", binary)
        bundle.writestr("geoip.dat", b"geo")
    return buffer.getvalue()


def test_release_is_verified_extracted_and_cached(tmp_path) -> None:
    archive = xray_zip(b"ELF-xray")
    pin = XrayRelease(version="v26.3.27", sha256={"x86_64": hashlib.sha256(archive).hexdigest()})
    upstream = FakeUpstream({URL: archive})

    with RuntimeDir() as runtime:
        first = resolver(
            upstream,
            tmp_path,
            runtime,
        ).resolve(pin, "x86_64", {})
        assert first.binary.read_bytes() == b"ELF-xray"
    with RuntimeDir() as runtime:
        again = resolver(
            upstream,
            tmp_path,
            runtime,
        ).resolve(pin, "x86_64", {})

    assert first.sha256 == hashlib.sha256(b"ELF-xray").hexdigest() == again.sha256
    assert upstream.downloads == [URL]


def test_release_with_wrong_sha256_is_refused_and_not_cached(tmp_path) -> None:
    pin = XrayRelease(version="v26.3.27", sha256={"x86_64": "0" * 64})

    with RuntimeDir() as runtime, pytest.raises(Refused):
        resolver(
            FakeUpstream({URL: xray_zip(b"evil")}),
            tmp_path,
            runtime,
        ).resolve(pin, "x86_64", {})

    assert not (tmp_path / "xray" / "v26.3.27" / "Xray-linux-64.zip").exists()


def test_two_releases_for_one_arch_keep_separate_binaries(tmp_path) -> None:
    newer_url = URL.replace("v26.3.27", "v26.9.9")
    old_zip, new_zip = xray_zip(b"ELF-old"), xray_zip(b"ELF-new")
    old = XrayRelease(version="v26.3.27", sha256={"x86_64": hashlib.sha256(old_zip).hexdigest()})
    new = XrayRelease(version="v26.9.9", sha256={"x86_64": hashlib.sha256(new_zip).hexdigest()})

    with RuntimeDir() as runtime:
        res = resolver(
            FakeUpstream({URL: old_zip, newer_url: new_zip}),
            tmp_path,
            runtime,
        )
        first = res.resolve(
            old,
            "x86_64",
            {},
        )
        second = res.resolve(
            new,
            "x86_64",
            {},
        )

        assert (first.binary.read_bytes(), second.binary.read_bytes()) == (b"ELF-old", b"ELF-new")


def test_head_pin_needs_provided_artifact(tmp_path) -> None:
    built = tmp_path / "xray-amd64"
    built.write_bytes(b"ELF-head")

    with RuntimeDir() as runtime:
        res = resolver(
            FakeUpstream(),
            tmp_path,
            runtime,
        )
        artifact = res.resolve(
            HEAD,
            "x86_64",
            {"x86_64": built},
        )
        with pytest.raises(Refused):
            res.resolve(
                HEAD,
                "aarch64",
                {"x86_64": built},
            )

    assert (artifact.label, artifact.sha256) == (HEAD, hashlib.sha256(b"ELF-head").hexdigest())


def test_malformed_string_pin_is_invalid() -> None:
    assert head_commit(HEAD) == "a" * 40
    with pytest.raises(InvalidManifest):
        head_commit("main@latest")


def test_artifact_option_requires_known_arch_and_file(tmp_path) -> None:
    built = tmp_path / "xray"
    built.write_bytes(b"x")

    assert parse_artifact_options([f"aarch64={built}"]) == {"aarch64": built.resolve()}
    with pytest.raises(UsageProblem):
        parse_artifact_options([f"arm64={built}"])
    with pytest.raises(UsageProblem):
        parse_artifact_options([f"x86_64={tmp_path / 'missing'}"])
