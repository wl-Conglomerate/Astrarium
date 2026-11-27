"""Masking of HexRift-rendered configs covering every inbound kind."""

import base64
import json
import re
import shutil
from typing import Any

import pytest
import yaml

from astrarium.components.secrets.masking import MASK, ValueMasker, mask_structure, secret_leaves
from astrarium.runtime import RuntimeDir
from tests.support.deployment import FIXTURE, fixture_app, generate_keys, make_deployment


pytestmark = pytest.mark.component

ALL_INBOUNDS = FIXTURE.parent / "topology-all-inbounds.yaml"

EXTRA_NODES = {
    "deA00": "exit",
    "jpA00": "exit",
    "spbA00": "hub",
}

UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

SHORT_ID_KEYS = ("shortId", "shortIds")


def _encodings(value: str) -> set[str]:
    """`value`, plus standard/urlsafe x padded/unpadded encodings of its bytes when it is base64."""

    found = {value}
    body = value.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        raw = base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except ValueError:
        return found
    for encoded in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
        found |= {encoded, encoded.rstrip("=")}
    return {form for form in found if len(form) >= ValueMasker.MIN_LENGTH}


def _values_under(obj: Any, keys: tuple[str, ...]) -> set[str]:
    if isinstance(obj, dict):
        found = {str(leaf) for key, value in obj.items() if key in keys for leaf in secret_leaves(value)}
        return found.union(*(_values_under(value, keys) for value in obj.values()))
    if isinstance(obj, list):
        return set().union(*(_values_under(item, keys) for item in obj))
    return set()


@pytest.fixture(scope="module")
def rendered(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict[str, str], ValueMasker, set[str]]:
    """Rendered config.json per node, masker seeded by prepare, every key file value."""

    root = make_deployment(tmp_path_factory.mktemp("all-inbounds") / "repo", keys=False)
    shutil.copyfile(ALL_INBOUNDS, root / "topology.yaml")
    manifest = yaml.safe_load((root / "astrarium.yaml").read_text())
    for offset, (node_id, role) in enumerate(sorted(EXTRA_NODES.items()), start=40):
        manifest["nodes"][node_id] = {"role": role, "ipv4": f"203.0.113.{offset}"}
    (root / "astrarium.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
    app = fixture_app(root)
    generate_keys(root, app.sops)
    with RuntimeDir() as runtime:
        ctx = app.topology.prepare(runtime, need_keys=True)
        assert ctx.keys_dir is not None
        built = app.topology.build(
            ctx,
            sorted(ctx.hexrift),
            runtime.sub("build"),
        )
        texts = {node_id: node.config_json.read_text() for node_id, node in built.items()}
        key_values = {
            leaf
            for key_file in ctx.keys_dir.glob("*.yaml")
            for leaf in secret_leaves(yaml.safe_load(key_file.read_text()))
        }
    return (
        texts,
        ctx.masker,
        key_values,
    )


def test_value_masking_hides_key_material_and_derived_identities_in_raw_text(rendered):
    texts, masker, key_values = rendered
    key_forms = {form for value in key_values for form in _encodings(value)}
    for node_id, raw in texts.items():
        hidden = key_forms | set(UUID.findall(raw)) | _values_under(json.loads(raw), SHORT_ID_KEYS)
        masked = masker.mask(raw)
        assert sorted(value for value in hidden if value in masked) == [], node_id


def test_post_build_harvest_masks_derived_hysteria_secrets_in_free_text(rendered):
    """deA00's obfs password and self-signed cert key are derived at render, absent from key files."""

    texts, masker, _ = rendered
    hysteria = next(inbound for inbound in json.loads(texts["deA00"])["inbounds"] if inbound["tag"] == "hysteria-in")
    stream = hysteria["streamSettings"]
    obfs_password = stream["finalmask"]["udp"][0]["settings"]["password"]
    cert_key_lines = stream["tlsSettings"]["certificates"][0]["key"]
    assert len(obfs_password) >= ValueMasker.MIN_LENGTH
    log_line = f"xray -test: hysteria obfs secret {obfs_password} accepted"
    assert masker.mask(log_line) == f"xray -test: hysteria obfs secret {MASK} accepted"
    long_lines = [line for line in cert_key_lines if len(line) >= ValueMasker.MIN_LENGTH]
    assert long_lines
    for line in long_lines:
        assert masker.mask(f"payload log line: {line}") == f"payload log line: {MASK}"


def test_post_build_harvest_does_not_mask_the_literal_word_password(rendered):
    """mskA00's mixed-protocol inbound has settings.auth == 'password' (xray's literal mode selector,
    not secret) alongside real accounts[].pass credential, only real credential is masked.
    """

    texts, masker, _ = rendered
    proxy = next(inbound for inbound in json.loads(texts["mskA00"])["inbounds"] if inbound["tag"] == "mixed-inbound")
    assert proxy["settings"]["auth"] == "password"
    real_password = proxy["settings"]["accounts"][0]["pass"]
    assert len(real_password) >= ValueMasker.MIN_LENGTH
    assert masker.mask("free text mentions the word password in the clear") == (
        "free text mentions the word password in the clear"
    )
    assert masker.mask(f"proxy account secret {real_password} end") == f"proxy account secret {MASK} end"


def test_structural_then_value_masking_leaves_no_secret_in_rendered_configs(rendered):
    texts, masker, key_values = rendered
    everything = "\n".join(texts.values())
    assert "PRIVATE KEY" in everything and '"secretKey"' in everything and UUID.search(everything)
    key_forms = {form for value in key_values for form in _encodings(value)}
    for node_id, raw in texts.items():
        structural = _values_under(
            json.loads(raw),
            (
                "secretKey",
                "pass",
                "key",
            ),
        )
        hidden = key_forms | {value for value in structural if len(value) >= ValueMasker.MIN_LENGTH}
        masked = masker.mask(json.dumps(mask_structure(json.loads(raw)), indent=2))
        assert "PRIVATE KEY" not in masked, node_id
        assert not UUID.search(masked), node_id
        assert sorted(value for value in hidden if value in masked) == [], node_id
