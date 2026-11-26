"""Throwaway TLS material and path rewrites so configs load outside their node."""

from __future__ import annotations

import datetime
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


STANDIN_NAME = "astrarium-check.invalid"

_BASE_DIRECTIVE = re.compile(r"^(?P<indent>[ \t]*)(?P<kind>crt-base|key-base)[ \t]+\S+[ \t]*$", re.MULTILINE)

_STATS_SOCKET = re.compile(r"^(?P<head>[ \t]*stats[ \t]+socket[ \t]+)\S+", re.MULTILINE)

_LOAD_LINE = re.compile(r"^(?P<indent>[ \t]*)load[ \t]+(?P<rest>.*)$", re.MULTILINE)

_LOAD_FILE = re.compile(r'\b(?P<kind>crt|key)[ \t]+"?(?P<path>[^"\s]+)"?')

_HAS_KEY = re.compile(r"\bkey[ \t]")

XRAY_LOG_FILES = ("access", "error")

XRAY_LOG_OFF = ("", "none")
"""log.access/log.error values naming no file: empty logs to console, `none` disables."""


@dataclass(frozen=True)
class TlsPair:
    """PEM certificate and private key files."""

    cert: Path
    key: Path


def make_tls_pair(dest: Path) -> TlsPair:
    """Self-signed P-256 pair valid 30 days, written to `dest`."""

    dest.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, STANDIN_NAME)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(STANDIN_NAME)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    pair = TlsPair(cert=dest / "standin.crt", key=dest / "standin.key")
    pair.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    pair.key.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return pair


def xray_test_config(config: Any, pair: TlsPair, workdir: Path) -> Any:
    """Copy of xray config: every certificateFile/keyFile set to stand-in pair, log files moved into `workdir`."""

    copy = _with_pair(config, pair)
    log = copy.get("log") if isinstance(copy, dict) else None
    if isinstance(log, dict):
        for kind in XRAY_LOG_FILES:
            value = log.get(kind)
            if isinstance(value, str) and value not in XRAY_LOG_OFF:
                log[kind] = str(workdir / f"{kind}.log")
    return copy


def _with_pair(config: Any, pair: TlsPair) -> Any:
    if isinstance(config, list):
        return [_with_pair(item, pair) for item in config]
    if not isinstance(config, dict):
        return config
    copy = {key: _with_pair(value, pair) for key, value in config.items()}
    if "certificateFile" in copy:
        copy["certificateFile"] = str(pair.cert)
    if "keyFile" in copy:
        copy["keyFile"] = str(pair.key)
    return copy


def haproxy_test_config(text: str, workdir: Path, pair: TlsPair) -> str:
    """Copy of haproxy.cfg with crt/key bases, loaded files and stats socket inside `workdir`."""

    pki = workdir / "pki"
    pki.mkdir(mode=0o755, exist_ok=True)
    text = _BASE_DIRECTIVE.sub(lambda m: f"{m['indent']}{m['kind']} {pki}", text)
    text = _STATS_SOCKET.sub(lambda m: f"{m['head']}{workdir / 'admin.sock'}", text)
    return _LOAD_LINE.sub(lambda m: _rewrite_load(m, pki, pair), text)


def _rewrite_load(line: re.Match[str], pki: Path, pair: TlsPair) -> str:
    separate_key = bool(_HAS_KEY.search(line["rest"]))

    def place(ref: re.Match[str]) -> str:
        target = pki / Path(ref["path"]).name
        if ref["kind"] == "key":
            content = pair.key.read_bytes()
        elif separate_key:
            content = pair.cert.read_bytes()
        else:
            content = pair.cert.read_bytes() + pair.key.read_bytes()
        target.write_bytes(content)
        return f'{ref["kind"]} "{target}"'

    return f"{line['indent']}load {_LOAD_FILE.sub(place, line['rest'])}"
