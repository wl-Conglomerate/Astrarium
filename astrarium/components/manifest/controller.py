"""Effective manifest views: `config show`, `config schema`."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.layering import leaf_paths
from astrarium.components.manifest.models import XrayRelease
from astrarium.components.manifest.overlay import sensitive_feature_paths
from astrarium.components.manifest.schema import schema_text
from astrarium.components.secrets.masking import ValueMasker, mask_paths
from astrarium.core import BaseController
from astrarium.errors import UsageProblem
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


DEFAULT_LAYER = "default"


def layer_of(provenance: dict[str, str], path: str) -> str:
    """Layer that set `path`, else nearest ancestor's, else descendants' (masked subtrees), else default."""

    if path in provenance:
        return provenance[path]
    parts = path.split(".")
    for depth in range(
        len(parts) - 1,
        0,
        -1,
    ):
        ancestor = ".".join(parts[:depth])
        if ancestor in provenance:
            return provenance[ancestor]
    below = sorted({layer for known, layer in provenance.items() if known.startswith(f"{path}.")})
    return ",".join(below) if below else DEFAULT_LAYER


def node_view(node: EffectiveNode, masker: ValueMasker, *, defaults: bool) -> dict[str, Any]:
    """JSON-ready view of one node: identity, derived values and masked values with their layer."""

    versions = {name: pin.model_dump() if isinstance(pin, XrayRelease) else pin for name, pin in node.versions.items()}
    data = {
        "features": mask_paths(node.features, sensitive_feature_paths()),
        "system": node.system,
        "versions": versions,
    }
    values = []
    for path, value in leaf_paths(data):
        layer = layer_of(node.provenance, path)
        if layer == DEFAULT_LAYER and not defaults:
            continue
        values.append(
            {
                "path": path,
                "value": json.loads(masker.mask(json.dumps(value))),
                "layer": layer,
            }
        )
    return {
        "role": node.role,
        "root_role": node.root_role,
        "managed_by": ["deploy", "casts"] if node.is_hexrift else ["casts"],
        "region": node.region,
        "fqdn": node.fqdn,
        "system_hostname": node.system_hostname,
        "ipv4": node.ipv4,
        "ipv6": node.ipv6,
        "arch": node.arch,
        "ssh": {
            "port": node.ssh_port,
            "user": node.ssh_user,
            "admin_user": node.admin_user,
        },
        "values": values,
    }


class ManifestController(BaseController["AstrariumApp"]):
    """Read-only manifest views, never prints."""

    def schema_text(self) -> str:
        return schema_text()

    def show(self, node_ids: list[str], *, defaults: bool = False) -> dict[str, dict[str, Any]]:
        """Effective data per node (all nodes when `node_ids` is empty), secrets masked, layer per value."""

        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=False)
            unknown = sorted(set(node_ids) - set(ctx.nodes))
            if unknown:
                raise UsageProblem(f"unknown node ids: {', '.join(unknown)}")
            wanted = node_ids or sorted(ctx.nodes)
            return {
                node_id: node_view(
                    ctx.nodes[node_id],
                    ctx.masker,
                    defaults=defaults,
                )
                for node_id in wanted
            }
