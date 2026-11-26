"""Minimal wheel builder for offline uv tests."""

from __future__ import annotations

import base64
import hashlib
import zipfile
from pathlib import Path


def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def build_wheel(dest: Path, name: str, version: str) -> Path:
    """Pure-python wheel `<name>-<version>-py3-none-any.whl` holding only `__version__`."""

    dist = f"{name}-{version}.dist-info"
    files = {
        f"{name}/__init__.py": f"__version__ = {version!r}\n".encode(),
        f"{dist}/METADATA": f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n".encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nGenerator: astrarium-tests\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
    }
    record = "".join(f"{path},{_record_hash(data)},{len(data)}\n" for path, data in files.items())
    record += f"{dist}/RECORD,,\n"
    dest.mkdir(parents=True, exist_ok=True)
    wheel = dest / f"{name}-{version}-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for path, data in files.items():
            archive.writestr(path, data)
        archive.writestr(f"{dist}/RECORD", record)
    return wheel
