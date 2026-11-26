"""Throwaway namespace and overlay stand-ins."""

from __future__ import annotations

import pytest
import yaml
from nullforge.molds import TelemtMold
from nullforge.molds.user import UsersMold

from astrarium.components.check.throwaway import random_namespace, standin_overlay
from astrarium.components.topology.bridge import NAMESPACE_PATTERN
from tests.support.check_repo import ENC


pytestmark = pytest.mark.unit


def test_random_namespace_is_fresh_128_bit_dns_safe_value() -> None:
    first, second = random_namespace(), random_namespace()

    assert NAMESPACE_PATTERN.fullmatch(first)
    assert len(first) >= 32
    assert not isinstance(yaml.safe_load(first), int | float)
    assert first != second


def test_standin_overlay_satisfies_nullforge_validators() -> None:
    encrypted = {
        "topology": {"namespace": ENC.format(kind="str")},
        "roles": {
            "pulsar": {
                "features": {
                    "telemt": {
                        "users": {
                            "alice": ENC.format(kind="str"),
                        }
                    },
                    "users": {
                        "users": [
                            {
                                "name": ENC.format(kind="str"),
                                "role": ENC.format(kind="str"),
                            },
                        ]
                    },
                }
            }
        },
        "numbers": {
            "count": ENC.format(kind="int"),
            "flag": ENC.format(kind="bool"),
            "ratio": ENC.format(kind="float"),
        },
        "plain": "kept",
        "sops": {"mac": ENC.format(kind="str")},
    }

    standin = standin_overlay(encrypted)

    assert "sops" not in standin
    features = standin["roles"]["pulsar"]["features"]
    TelemtMold.model_validate(
        {
            "install": True,
            "tls_domain": "www.example.com",
            "users": features["telemt"]["users"],
        }
    )
    UsersMold.model_validate(features["users"])
    assert standin["numbers"]["count"] == 0
    assert standin["numbers"]["flag"] is False
    assert standin["numbers"]["ratio"] == 0.0
    assert standin["plain"] == "kept"
