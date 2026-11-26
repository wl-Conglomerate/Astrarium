"""Real sops round trip, skipped unless sops and age-keygen are on PATH (tool CI requires them)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from astrarium.components.secrets.sops import Sops


REQUIRED = os.environ.get("ASTRARIUM_REAL_SOPS") == "required"

pytestmark = [
    pytest.mark.component,
    pytest.mark.skipif(
        not REQUIRED and (shutil.which("sops") is None or shutil.which("age-keygen") is None),
        reason="needs sops and age-keygen",
    ),
]


def test_real_sops_encrypts_decrypts_updates_and_rotates(tmp_path: Path):
    key_file = tmp_path / "age.key"
    subprocess.run(
        [
            "age-keygen",
            "-o",
            str(key_file),
        ],
        check=True,
        capture_output=True,
    )
    recipient = next(line.split()[-1] for line in key_file.read_text().splitlines() if "public key" in line)
    repo = tmp_path / "repo"
    (repo / "secrets" / "keys").mkdir(parents=True)
    (repo / ".sops.yaml").write_text(
        f"creation_rules:\n  - path_regex: (^|/)secrets/.*\\.ya?ml$\n    age: {recipient}\n"
    )
    sops = Sops(
        env={
            "PATH": str(Path(shutil.which("sops") or "").parent),
            "HOME": str(tmp_path),
            "SOPS_AGE_KEY_FILE": str(key_file),
        }
    )
    target = repo / "secrets" / "keys" / "nlA00.yaml"
    target.write_bytes(
        sops.encrypt(
            b"reality_private_key: abc123\n",
            filename_override=Path("secrets/keys/nlA00.yaml"),
            cwd=repo,
        )
    )
    assert Sops.has_metadata(target)
    assert "abc123" not in target.read_text()
    assert yaml.safe_load(sops.decrypt(target)) == {"reality_private_key": "abc123"}
    sops.updatekeys(target)
    sops.rotate(target)
    assert yaml.safe_load(sops.decrypt(target)) == {"reality_private_key": "abc123"}
