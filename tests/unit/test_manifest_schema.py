"""Generated manifest JSON schema stays in sync with model constraints."""

import pytest

from astrarium.components.manifest.schema import manifest_schema


pytestmark = pytest.mark.unit


def test_schema_forbids_unknown_top_level_keys():
    schema = manifest_schema()
    assert schema["additionalProperties"] is False
    assert {"deployment", "nodes"} <= set(schema["required"])
