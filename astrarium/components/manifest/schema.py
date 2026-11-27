"""JSON schema of astrarium.yaml, generated from manifest model."""

from __future__ import annotations

import json
from typing import Any

from astrarium.components.manifest.models import Manifest


def manifest_schema() -> dict[str, Any]:
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", **Manifest.model_json_schema()}


def schema_text() -> str:
    return (
        json.dumps(
            manifest_schema(),
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
