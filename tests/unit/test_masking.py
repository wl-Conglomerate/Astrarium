"""Structural and value masking."""

import base64
import json

import pytest

from astrarium.components.secrets.masking import (
    MASK,
    ValueMasker,
    ci_mask_hook,
    haproxy_secret_values,
    mask_haproxy,
    mask_paths,
    mask_structure,
    secret_json_leaves,
    secret_leaves,
)


pytestmark = pytest.mark.unit

SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_mask_structure_redacts_secret_keys_at_any_depth():
    config = {
        "inbounds": [{"settings": {"clients": [{"id": "uuid-1", "flow": "xtls-rprx-vision"}], "decryption": "mlkem"}}],
        "streamSettings": {
            "realitySettings": {
                "privateKey": "pk",
                "shortIds": ["aa", "bb"],
                "serverNames": ["www.example.com"],
            }
        },
    }
    masked = mask_structure(config)
    assert masked["inbounds"][0]["settings"]["clients"][0] == {"id": MASK, "flow": "xtls-rprx-vision"}
    assert masked["inbounds"][0]["settings"]["decryption"] == MASK
    assert masked["streamSettings"]["realitySettings"] == {
        "privateKey": MASK,
        "shortIds": MASK,
        "serverNames": ["www.example.com"],
    }
    assert config["streamSettings"]["realitySettings"]["privateKey"] == "pk"


def test_mask_haproxy_redacts_credential_directives():
    text = "listen stats\n  stats auth admin:hunter2secret\nuserlist ops\n  user ops insecure-password hunter2secret\n"
    masked = mask_haproxy(text)
    assert "hunter2secret" not in masked
    assert "listen stats" in masked


def test_haproxy_secret_values_extracts_what_mask_haproxy_redacts():
    text = "listen stats\n  stats auth admin:hunter2secret\nuserlist ops\n  user ops insecure-password hunter2secret\n"
    assert set(haproxy_secret_values(text)) == {"admin:hunter2secret", "hunter2secret"}


def test_secret_json_leaves_skips_auth_when_it_is_an_xray_mode_literal():
    data = {
        "settings": {"auth": "password", "accounts": [{"user": "alice", "pass": "real-uuid-credential"}]},
        "other": {"auth": "noauth"},
    }
    assert set(secret_json_leaves(data)) == {"real-uuid-credential"}


def test_secret_json_leaves_single_string_pem_leaf_masks_each_line_in_free_text():
    pem = "-----BEGIN FAKE KEY-----\nfake-key-line-0001\nfake-key-line-0002\n-----END FAKE KEY-----"
    data = {"tlsSettings": {"certificates": [{"key": pem}]}}
    masker = ValueMasker()
    masker.add_many(secret_json_leaves(data))
    assert masker.mask("payload log line: fake-key-line-0001 end") == f"payload log line: {MASK} end"
    assert masker.mask(pem) == MASK


def test_secret_json_leaves_finds_values_nested_under_secret_keys_only():
    data = {
        "streamSettings": {
            "tlsSettings": {"certificates": [{"key": ["line-0001-aaaa", "line-0002-bbbb"], "certificate": ["pub"]}]}
        },
        "settings": {"clients": [{"password": "pw-value-123"}]},
        "note": "not-a-secret-key-value",
    }
    assert set(secret_json_leaves(data)) == {
        "line-0001-aaaa",
        "line-0002-bbbb",
        "pw-value-123",
    }


def test_value_masker_masks_raw_json_escaped_and_base64_forms():
    masker = ValueMasker()
    quoted = 'se"cret-value-with-quote'
    # Standard base64 is padded and contains '/', unlike SECRET/quoted's forms above,
    # so this exercises unpadded-standard and urlsafe forms distinctly.
    padded = "~QV;h?A!"
    masker.add_many(
        [
            SECRET,
            quoted,
            padded,
        ]
    )
    padded_std = base64.b64encode(padded.encode()).decode()
    unpadded_std = padded_std.rstrip("=")
    padded_urlsafe = base64.urlsafe_b64encode(padded.encode()).decode()
    unpadded_urlsafe = padded_urlsafe.rstrip("=")
    assert padded_std.endswith("=")
    assert "+" in padded_std or "/" in padded_std
    text = "\n".join(
        [
            SECRET,
            json.dumps(quoted),
            base64.b64encode(SECRET.encode()).decode(),
            base64.urlsafe_b64encode(quoted.encode()).decode().rstrip("="),
            unpadded_std,
            padded_urlsafe,
            unpadded_urlsafe,
        ]
    )
    masked = masker.mask(text)
    assert SECRET not in masked
    assert "cret-value" not in masked
    assert base64.b64encode(SECRET.encode()).decode() not in masked
    assert padded not in masked
    assert unpadded_std not in masked
    assert padded_urlsafe not in masked
    assert unpadded_urlsafe not in masked


def test_value_masker_masks_every_base64_encoding_of_base64_value():
    raw = bytes(
        [
            0xFB,
            0xFF,
            0xBF,
        ]
        * 10
        + [0xFE, 0xFF]
    )
    standard = base64.b64encode(raw).decode()
    assert "+" in standard and "/" in standard and standard.endswith("=")
    masker = ValueMasker()
    masker.add(base64.urlsafe_b64encode(raw).decode().rstrip("="))
    for form in (
        standard,
        standard.rstrip("="),
        base64.urlsafe_b64encode(raw).decode(),
    ):
        assert masker.mask(f"secretKey {form} end") == f"secretKey {MASK} end"


def test_on_add_notifies_once_per_newly_registered_form_including_base64():
    added: list[str] = []
    masker = ValueMasker(on_add=added.append)
    masker.add(SECRET)
    assert SECRET in added
    assert base64.b64encode(SECRET.encode()).decode() in added
    added.clear()
    masker.add(SECRET)
    assert added == []


def test_on_add_is_never_called_for_values_shorter_than_min_length():
    added: list[str] = []
    masker = ValueMasker(on_add=added.append)
    masker.add("short")
    assert added == []


def test_on_add_receives_a_multiline_value_whole_unsplit():
    added: list[str] = []
    masker = ValueMasker(on_add=added.append)
    pem = "-----BEGIN FAKE KEY-----\nfake-key-line-0001\n-----END FAKE KEY-----\n"
    masker.add(pem)
    assert pem in added


def test_on_add_does_not_also_fire_per_line_of_a_multiline_value():
    """Caller turning one on_add notification into per-line output (CLI add-mask hook)
    already covers every real line by splitting whole value: second, separate on_add call
    per line would make it emit each line twice.
    """

    added: list[str] = []
    masker = ValueMasker(on_add=added.append)
    pem = "-----BEGIN FAKE KEY-----\nfake-key-line-0001\n-----END FAKE KEY-----\n"
    masker.add(pem)
    assert "fake-key-line-0001" not in added
    assert "-----BEGIN FAKE KEY-----" not in added
    assert pem in added


def test_value_masker_ignores_short_values():
    masker = ValueMasker()
    masker.add("443")
    masker.add("true")
    assert masker.mask("port 443 enabled true") == "port 443 enabled true"


def test_secret_leaves_yields_scalars_skipping_none_and_bool():
    data = {
        "creds": {"token": "abc12345", "flag": True},
        "items": [
            {"id": "xyz789"},
            None,
            42,
            False,
            [
                "nested-leaf",
                None,
                True,
            ],
        ],
        "empty": None,
    }
    assert set(secret_leaves(data)) == {
        "abc12345",
        "xyz789",
        "42",
        "nested-leaf",
    }


def test_mask_paths_hides_sensitive_values_only():
    data = {"telemt": {"users": {"alice": SECRET}, "port": 443}, "users": {"users": [{"name": "a", "password": ""}]}}
    assert mask_paths(
        data,
        [
            "telemt.users",
            "users.users",
            "zerotrust.token",
        ],
    ) == {
        "telemt": {"users": MASK, "port": 443},
        "users": {"users": MASK},
    }


def test_ci_mask_hook_writes_add_mask_lines_to_stderr_only_in_ci(monkeypatch, capsys):
    assert ci_mask_hook() is None
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    hook = ci_mask_hook()
    assert hook is not None
    hook("-----BEGIN FAKE KEY-----\nfake-key-line-0001\nshort\npct-%-line-0001\n")
    assert capsys.readouterr().err.splitlines() == [
        "::add-mask::-----BEGIN FAKE KEY-----",
        "::add-mask::fake-key-line-0001",
        "::add-mask::pct-%25-line-0001",
    ]
