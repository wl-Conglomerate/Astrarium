"""Stand-ins let xray and haproxy load configs without real certificates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from astrarium.components.check.standins import TlsPair, haproxy_test_config, make_tls_pair, xray_test_config


pytestmark = pytest.mark.component

HEXRIFT_HAPROXY = """\
global
  log /dev/log local0
  stats socket /run/haproxy/admin.sock mode 660 expose-fd listeners
  daemon

crt-store certs
  crt-base /usr/local/etc/haproxy/pki
  key-base /usr/local/etc/haproxy/pki
  load crt "cdn-hub.pem" key "cdn-hub.key" alias "cdn-hub"

frontend fe_cdn_https_local
  mode http
  bind unix@/dev/shm/haproxy_cdn_https_local.sock ssl crt "@certs/cdn-hub" ssl-min-ver TLSv1.2 accept-proxy alpn \
h2,http/1.1
"""


def test_tls_pair_key_matches_certificate(tmp_path: Path) -> None:
    pair = make_tls_pair(tmp_path / "tls")

    cert = x509.load_pem_x509_certificate(pair.cert.read_bytes())
    key = serialization.load_pem_private_key(pair.key.read_bytes(), password=None)

    encoding, public_format = serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    assert cert.public_key().public_bytes(encoding, public_format) == key.public_key().public_bytes(
        encoding, public_format
    )


def test_xray_test_config_points_every_certificate_at_pair(tmp_path: Path) -> None:
    pair = TlsPair(cert=tmp_path / "c.pem", key=tmp_path / "k.pem")
    config = {
        "inbounds": [
            {
                "streamSettings": {
                    "tlsSettings": {
                        "certificates": [
                            {
                                "certificateFile": "/usr/local/etc/xray/certs/fullchain.pem",
                                "keyFile": "/usr/local/etc/xray/certs/privkey.pem",
                            }
                        ]
                    }
                }
            },
            {"settings": {"certificateFile": "/etc/hy/cert.pem", "keyFile": "/etc/hy/key.pem"}},
        ]
    }

    text = json.dumps(
        xray_test_config(
            config,
            pair,
            tmp_path,
        )
    )

    assert "/usr/local/etc/xray" not in text
    assert "/etc/hy/" not in text
    assert text.count(str(pair.cert)) == 2
    assert text.count(str(pair.key)) == 2
    assert config["inbounds"][1]["settings"]["keyFile"] == "/etc/hy/key.pem"


def test_xray_test_config_moves_log_files_into_workdir(tmp_path: Path) -> None:
    pair = TlsPair(cert=tmp_path / "c.pem", key=tmp_path / "k.pem")
    workdir = tmp_path / "work"
    config = {
        "log": {
            "access": "/var/log/xray/access.log",
            "error": "none",
            "loglevel": "warning",
        }
    }

    log = xray_test_config(
        config,
        pair,
        workdir,
    )["log"]

    assert Path(log["access"]).is_relative_to(workdir)
    assert log["error"] == "none"


def test_haproxy_test_config_moves_pki_and_socket_into_workdir(tmp_path: Path) -> None:
    pair = make_tls_pair(tmp_path / "tls")
    workdir = tmp_path / "work"
    workdir.mkdir()

    text = haproxy_test_config(
        HEXRIFT_HAPROXY,
        workdir,
        pair,
    )

    assert "/usr/local/etc/haproxy/pki" not in text
    assert "/run/haproxy/admin.sock" not in text
    assert (workdir / "pki" / "cdn-hub.pem").read_bytes() == pair.cert.read_bytes()
    assert (workdir / "pki" / "cdn-hub.key").read_bytes() == pair.key.read_bytes()
    assert 'crt "@certs/cdn-hub"' in text
