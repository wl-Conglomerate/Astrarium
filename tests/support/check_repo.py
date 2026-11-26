"""Deployment fixtures for check tests: HexRift topology, sops-shaped overlay, git history."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from astrarium.components.topology.bridge import NAMESPACE_PLACEHOLDER
from tests.support.deployment import git_commit_all


XRAY_SHA = "0123456789abcdef0123456789abcdef01234567"

AGE_A = "age1" + "q" * 58

ENC = "ENC[AES256_GCM,data:c3RhbmRpbg==,iv:aXY=,tag:dGFn,type:{kind}]"

"""sops value shape; `kind` is sops' stored type (str, int, float, bool)."""

TOPOLOGY = f"""\
global:
  namespace: {NAMESPACE_PLACEHOLDER}
  aphelion_domain: aphelion.example.net

defaults:
  exit:
    ipv6: false
    keys:
      auth: x25519
      mode: native
      session_time: 600s
  hub:
    ipv6: false
    keys:
      auth: x25519
      mode: native
      session_time: 600s
    exit_connections:
      method: mlkem768x25519plus
      fingerprint: chrome
    reality:
      dest: www.example.com:443
    xhttp:
      path: /update/

groups:
  - id: main
    short_id: "aabbccddeeff0011"

users:
  - username: alice
    group: main
    access: [xhttp, tls]

routing:
  hub_default: nl

regions:
  - id: nl
    type: exit
    vless_route: 1000
    nodes:
      - id: nlA00
        hostname: nlA00.aphelion.example.net
        reality:
          dest: www.example.com:443
        xhttp:
          path: /update/
  - id: msk
    type: hub
    nodes:
      - id: mskA00
        hostname: mskA00.perigee.example.net
  - id: spb
    type: hub
    tls:
      certificate:
        cert_file: /usr/local/etc/xray/certs/fullchain.pem
        key_file: /usr/local/etc/xray/certs/privkey.pem
    xhttp:
      path: /tls/
    nodes:
      - id: spbA00
        hostname: spbA00.perigee.example.net
"""

DE_REGION = """\
  - id: de
    type: exit
    vless_route: 2000
    nodes:
      - id: deA00
        hostname: deA00.aphelion.example.net
        reality:
          dest: www.example.com:443
        xhttp:
          path: /update/
"""

NL_NODE = "      - id: nlA00\n        hostname: nlA00.aphelion.example.net\n"


def with_extra_exit(topology: str) -> str:
    return topology + DE_REGION


def with_nl_keys_disabled(topology: str) -> str:
    return topology.replace(
        "  - id: nl\n    type: exit\n    vless_route: 1000\n    nodes:\n"
        "      - id: nlA00\n        hostname: nlA00.aphelion.example.net\n"
        "        reality:\n          dest: www.example.com:443\n        xhttp:\n          path: /update/\n",
        "  - id: nl\n    type: exit\n    transport: tcp\n    vless_route: 1000\n    nodes:\n"
        "      - id: nlA00\n        hostname: nlA00.aphelion.example.net\n"
        "        reality:\n          dest: www.example.com:443\n",
    ).replace(NL_NODE, NL_NODE + "        keys:\n          enabled: false\n")


def manifest_data() -> dict[str, Any]:
    return {
        "deployment": {
            "name": "test",
            "domain": "example.net",
            "names": {
                "exit": "aphelion",
                "hub": "perigee",
                "pulsar": "pulsar",
            },
        },
        "roles": {
            "exit": {"features": {"haproxy": {"install": True, "version": "3.2"}}},
            "hub": {"features": {"haproxy": {"install": True, "version": "3.2"}}},
            "pulsar": {"features": {"telemt": {"install": True, "tls_domain": "www.example.com"}}},
        },
        "versions": {"xray": f"main@{XRAY_SHA}"},
        "nodes": {
            "nlA00": {"role": "exit", "ipv4": "203.0.113.10"},
            "mskA00": {"role": "hub", "ipv4": "203.0.113.20"},
            "spbA00": {"role": "hub", "ipv4": "203.0.113.30"},
            "mskP00": {"role": "pulsar", "ipv4": "203.0.113.40"},
        },
    }


def overlay_text(recipient: str = AGE_A) -> str:
    return f"""\
topology:
    namespace: {ENC.format(kind="str")}
roles:
    pulsar:
        features:
            telemt:
                users:
                    alice: {ENC.format(kind="str")}
sops:
    age:
        - recipient: {recipient}
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            c3RhbmRpbg==
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2026-09-25T00:00:00Z"
    mac: {ENC.format(kind="str")}
    version: 3.13.3
"""


def uv_lock_text(hexrift: str = "0.13.0") -> str:
    return (
        'version = 1\nrevision = 3\nrequires-python = ">=3.13"\n\n'
        f'[[package]]\nname = "hexrift"\nversion = "{hexrift}"\n'
        'source = { registry = "https://photon.example.invalid/simple/" }\n'
    )


def sops_config_text(*recipients: str) -> str:
    """`.sops.yaml` with one rule for secrets/."""

    joined = ",".join(recipients or (AGE_A,))
    return f'creation_rules:\n  - path_regex: (^|/)secrets/.*\\.ya?ml$\n    age: "{joined}"\n'


def write_deployment(
    root: Path,
    *,
    manifest: dict[str, Any] | None = None,
    topology: str = TOPOLOGY,
    recipient: str = AGE_A,
    hexrift: str = "0.13.0",
) -> Path:
    """Write deployment files into `root` without committing."""

    root.mkdir(parents=True, exist_ok=True)
    data = manifest if manifest is not None else manifest_data()
    (root / "astrarium.yaml").write_text(yaml.safe_dump(data, sort_keys=False))
    (root / "topology.yaml").write_text(topology)
    (root / "secrets" / "keys").mkdir(parents=True, exist_ok=True)
    (root / "secrets" / "astrarium.sops.yaml").write_text(overlay_text(recipient))
    (root / ".sops.yaml").write_text(sops_config_text(recipient))
    (root / "uv.lock").write_text(uv_lock_text(hexrift))
    return root


def make_check_repo(root: Path, **files: Any) -> Path:
    """Repo on main with one commit holding full deployment, `files` go to write_deployment."""

    write_deployment(root, **files)
    git_commit_all(root, "base")
    return root
