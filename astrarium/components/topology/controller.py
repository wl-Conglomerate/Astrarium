"""Build pipeline shared by build, deploy, status and casts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from hexrift.app import HexRiftApp

from astrarium.components.manifest.derive import EffectiveNode, effective_nodes
from astrarium.components.manifest.loader import load_manifest
from astrarium.components.manifest.models import Manifest
from astrarium.components.manifest.overlay import overlay_namespace
from astrarium.components.rollout.selection import select
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.secrets.masking import (
    ValueMasker,
    ci_mask_hook,
    haproxy_secret_values,
    secret_json_leaves,
    secret_leaves,
)
from astrarium.components.topology.bridge import (
    BuiltNode,
    HexRiftNode,
    build_nodes,
    derived_identities,
    hexrift_nodes,
    materialize_topology,
    open_hexrift,
)
from astrarium.core import BaseController
from astrarium.errors import InvalidManifest, Refused, UsageProblem
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


HEXRIFT_READ_COMMANDS = frozenset(
    {
        "share",
        "derive",
        "show",
        "validate",
    }
)

KEYS_SUBDIR = "keys"


@dataclass
class BuildContext:
    """Decrypted, derived state of one run, lives only inside its RuntimeDir."""

    runtime: RuntimeDir
    manifest: Manifest
    overlay: dict[str, Any]
    topology: Path
    app: HexRiftApp
    hexrift: dict[str, HexRiftNode]
    nodes: dict[str, EffectiveNode]
    keys_dir: Path | None
    masker: ValueMasker


def consistency_problems(
    manifest: Manifest,
    nodes: Mapping[str, EffectiveNode],
    hexrift: Mapping[str, HexRiftNode],
) -> list[str]:
    """Hub/exit sets of manifest and topology differ, or root roles do not match region types."""

    manifest_hexrift = {node_id for node_id, node in nodes.items() if node.is_hexrift}
    problems = [
        f"{node_id}: in topology.yaml, missing from astrarium.yaml" for node_id in sorted(set(hexrift) - set(nodes))
    ]
    problems += [
        f"{node_id}: hub/exit in astrarium.yaml, missing from topology.yaml"
        for node_id in sorted(manifest_hexrift - set(hexrift))
    ]
    for node_id in sorted(set(hexrift) & set(nodes)):
        node, region = nodes[node_id], hexrift[node_id]
        if node.root_role != region.type:
            problems.append(f"{node_id}: root role {node.root_role} but {region.type} region {region.region}")
    return problems


def require_domain(manifest: Manifest) -> None:
    """Refused: no HexRift release supports hostname-less exit links yet."""

    if manifest.deployment.domain is None:
        raise Refused(
            "IP-only deployments are not supported yet (deployment.domain missing)",
            hint="IP-only deployments need a HexRift release with hostname-based exit links",
        )


def derive_checked(
    manifest: Manifest,
    topology_src: Path,
    dest: Path,
    namespace: str,
) -> tuple[HexRiftApp, dict[str, HexRiftNode], dict[str, EffectiveNode]]:
    """Materialize topology, open HexRift, derive nodes, refuse hub/exit mismatch.

    Shared derive-and-check sequence for build/deploy (`TopologyController.prepare`) and
    `check.controller.load_build`, so both callers cannot drift apart.
    """

    topology = materialize_topology(
        topology_src,
        dest,
        namespace,
    )
    app = open_hexrift(topology)
    hexrift = hexrift_nodes(app)
    nodes = effective_nodes(manifest, {node_id: node.region for node_id, node in hexrift.items()})
    problems = consistency_problems(
        manifest,
        nodes,
        hexrift,
    )
    if problems:
        raise InvalidManifest(
            "astrarium.yaml and topology.yaml disagree: " + "; ".join(problems), hint="run `arium repo doctor`"
        )
    return (
        app,
        hexrift,
        nodes,
    )


class TopologyController(BaseController["AstrariumApp"]):
    """Decrypt, derive and build into RuntimeDir, never generates keys."""

    def read_overlay(self) -> dict[str, Any]:
        """Decrypted overlay, InvalidManifest when missing."""

        repo = self.app.repo
        if not repo.overlay.is_file():
            raise InvalidManifest(f"{repo.overlay.relative_to(repo.root)} missing", hint="it holds topology.namespace")
        data = yaml.safe_load(self.app.sops.decrypt(repo.overlay))
        if data is None:
            return {}
        if not isinstance(data, dict):
            raise InvalidManifest("secrets overlay: top level must be a mapping")
        return data

    def prepare(self, runtime: RuntimeDir, *, need_keys: bool) -> BuildContext:
        """Decrypt overlay, load manifest, materialize topology, open HexRift, derive nodes, decrypt keys, mask.

        Masker holds namespace, overlay values, HexRift-derived identities and, with `need_keys`, key file
        values. Built with app's mask hook, so every value added here or later (rotated keys, build's
        post-render harvest) reaches CI's `::add-mask::` same way.
        """

        repo = self.app.repo
        overlay = self.read_overlay()
        manifest = load_manifest(repo, overlay)
        require_domain(manifest)
        namespace = overlay_namespace(overlay)
        if namespace is None:
            raise InvalidManifest(
                "secrets overlay lacks topology.namespace", hint="the real namespace lives in the overlay"
            )
        topology = runtime.sub("topology") / "topology.yaml"
        app, hexrift, nodes = derive_checked(
            manifest,
            repo.topology,
            topology,
            namespace,
        )
        masker = ValueMasker(on_add=ci_mask_hook())
        masker.add(namespace)
        masker.add_many(secret_leaves({key: value for key, value in overlay.items() if key != "sops"}))
        masker.add_many(derived_identities(app))
        keys_dir: Path | None = None
        if need_keys:
            keys_dir = KeyStore(repo, self.app.sops).decrypt_all(runtime.sub(KEYS_SUBDIR))
            for key_file in sorted(keys_dir.glob("*.yaml")):
                masker.add_many(secret_leaves(yaml.safe_load(key_file.read_text(encoding="utf-8"))))
        return BuildContext(
            runtime=runtime,
            manifest=manifest,
            overlay=overlay,
            topology=topology,
            app=app,
            hexrift=hexrift,
            nodes=nodes,
            keys_dir=keys_dir,
            masker=masker,
        )

    def require_keys(self, ctx: BuildContext, node_ids: Iterable[str]) -> None:
        """Refused (exit 4) naming hub/exit nodes without key file."""

        wanted = [node_id for node_id in node_ids if node_id in ctx.hexrift]
        missing = KeyStore(self.app.repo, self.app.sops).missing(wanted)
        if missing:
            raise Refused(
                f"no key file for {', '.join(missing)}", hint="run `arium keys gen` locally and commit secrets/keys/"
            )

    def build(self, ctx: BuildContext, node_ids: list[str], out_dir: Path) -> dict[str, BuiltNode]:
        """Render selected hub/exit nodes, hubs need every exit key (checked first).

        Harvests rendered config.json/haproxy.cfg for derived secrets (Hysteria obfs password,
        self-signed cert private key, HAProxy credential directives) absent from decrypted
        overlay/keys, registering them with ctx.masker so free-text output masks them too.
        """

        if ctx.keys_dir is None:
            raise RuntimeError("prepare(need_keys=True) is required before build")
        unknown = sorted(node_id for node_id in node_ids if node_id not in ctx.hexrift)
        if unknown:
            raise UsageProblem(f"not HexRift nodes: {', '.join(unknown)}")
        needed = set(node_ids)
        if any(ctx.hexrift[node_id].type == "hub" for node_id in node_ids):
            needed |= {node_id for node_id, node in ctx.hexrift.items() if node.type == "exit"}
        self.require_keys(ctx, sorted(needed))
        built = build_nodes(
            ctx.app,
            node_ids,
            ctx.keys_dir,
            out_dir,
        )
        for node in built.values():
            config = json.loads(node.config_json.read_text(encoding="utf-8"))
            ctx.masker.add_many(secret_json_leaves(config))
            ctx.masker.add_many(haproxy_secret_values(node.haproxy_cfg.read_text(encoding="utf-8")))
        return built

    def build_out(self, limit: str | None, out: Path) -> tuple[dict[str, BuiltNode], dict[str, str]]:
        """`arium fleet build --out`: render selected nodes into explicit 0700 dir outside repo."""

        target = out.expanduser().resolve()
        root = self.app.repo.root.resolve()
        if target == root or root in target.parents:
            raise UsageProblem(
                f"--out {out} is inside the deployment repo",
                hint="rendered configs hold private keys: pick a dir outside the repo",
            )
        if target.exists() and any(target.iterdir()):
            raise UsageProblem(f"--out {out} is not empty")
        with RuntimeDir() as runtime:
            ctx = self.prepare(runtime, need_keys=True)
            selection = select(
                ctx.nodes,
                limit,
                hexrift_only=True,
            )
            selected, skipped = selection.nodes, selection.skipped
            staged = self.build(
                ctx,
                selected,
                runtime.sub("build"),
            )
            target.mkdir(
                mode=0o700,
                parents=True,
                exist_ok=True,
            )
            target.chmod(0o700)
            result: dict[str, BuiltNode] = {}
            for node_id, built in staged.items():
                node_dir = target / node_id
                node_dir.mkdir(mode=0o700, exist_ok=True)
                for source in (built.config_json, built.haproxy_cfg):
                    fd = os.open(
                        node_dir / source.name,
                        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                        0o600,
                    )
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(source.read_bytes())
                result[node_id] = BuiltNode(
                    node_id,
                    node_dir / "config.json",
                    node_dir / "haproxy.cfg",
                    built.haproxy_wanted,
                )
        return result, skipped

    def hexrift(self, args: list[str]) -> int:
        """Run HexRift read command on temp topology with real namespace and decrypted keys, return its exit code."""

        if not args or args[0] not in HEXRIFT_READ_COMMANDS:
            raise UsageProblem(
                f"arium hexrift runs {', '.join(sorted(HEXRIFT_READ_COMMANDS))}",
                hint="edit topology with `hexrift nodes ...` on topology.yaml directly, build with `arium fleet build`",
            )
        with RuntimeDir() as runtime:
            ctx = self.prepare(runtime, need_keys=True)
            argv = [
                sys.executable,
                "-m",
                "hexrift",
                "--yaml",
                str(ctx.topology),
                *args,
            ]
            return subprocess.run(  # noqa: S603
                argv,
                cwd=runtime.path,
                check=False,
            ).returncode  # noqa: S603
