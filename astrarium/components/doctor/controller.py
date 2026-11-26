"""`arium repo doctor`: prerequisites, secrets, manifest, topology and consistency rules, never changes anything."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml

from astrarium.components.doctor import checks as rules
from astrarium.components.doctor.checks import Check
from astrarium.components.manifest.derive import EffectiveNode, effective_nodes
from astrarium.components.manifest.loader import load_manifest, read_raw
from astrarium.components.manifest.models import Manifest
from astrarium.components.manifest.overlay import overlay_namespace
from astrarium.components.secrets.controller import YAML_SUFFIXES, is_encrypted, secret_files
from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.topology.bridge import (
    HexRiftNode,
    build_nodes,
    hexrift_nodes,
    open_hexrift,
    topology_namespace,
)
from astrarium.core import BaseController
from astrarium.errors import AstrariumError
from astrarium.parallel import run_pool
from astrarium.repo import Repo
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from hexrift.app import HexRiftApp

    from astrarium.app import AstrariumApp


def _committed_topology(repo: Repo) -> dict[str, Any] | None:
    try:
        proc = subprocess.run(  # noqa: S603
            [  # noqa: S607
                "git",
                "-C",
                str(repo.root),
                "show",
                "HEAD:topology.yaml",
            ],  # noqa: S607
            capture_output=True,
            check=False,
        )
    except OSError:
        return None
    if proc.returncode != 0:
        return None
    try:
        data = yaml.safe_load(proc.stdout)
    except yaml.YAMLError:
        return None
    return data if isinstance(data, dict) else None


def dns_ignored_names(zone_file: Path) -> set[str]:
    """Record names of `zone_file` whose key carries `# astrarium:ignore` comment (ruamel round trip)."""

    from ruamel.yaml import YAML

    marked: set[str] = set()
    data = YAML().load(zone_file.read_text(encoding="utf-8"))
    if not hasattr(data, "ca"):
        return marked
    for key in data:
        for slot in data.ca.items.get(key, []):
            tokens = slot if isinstance(slot, list) else [slot]
            if any(
                rules.DNS_IGNORE_MARKER
                in str(
                    getattr(
                        token,
                        "value",
                        "",
                    )
                )
                for token in tokens
            ):
                marked.add(str(key))
    return marked


class DoctorController(BaseController["AstrariumApp"]):
    """Runs every rule it can: failing stage reports fail check and skips rules depending on it."""

    def run(self) -> list[Check]:
        found = [*rules.check_tools(shutil.which), *rules.check_environment(os.environ)]
        repo = self.app.repo
        found.append(rules.check_leftovers(RuntimeDir.leftovers()))
        overlay = self._secrets(repo, found)
        manifest = self._manifest(
            repo,
            overlay,
            found,
        )
        topology = self._topology(
            repo,
            overlay,
            found,
        )
        if manifest is None or topology is None:
            return found
        app, hexrift = topology
        nodes = self._nodes(
            manifest,
            hexrift,
            found,
        )
        if nodes is None:
            return found
        found += [
            rules.check_node_sets(
                manifest,
                nodes,
                hexrift,
            ),
            rules.check_key_files(nodes, KeyStore(repo, self.app.sops).node_ids()),
            rules.check_host_keys(nodes),
            rules.check_hostnames(
                manifest,
                nodes,
                hexrift,
                app.schema.config.global_.aphelion_domain,
            ),
            rules.check_jump(manifest, nodes),
            rules.check_ssh_sources(nodes),
            self._haproxy(
                repo,
                app,
                nodes,
                hexrift,
            ),
            self._lockfile(repo),
            *self._dns(
                repo,
                manifest,
                nodes,
            ),
            self._reality_dest(repo),
            rules.check_deploy_workflow((repo.workflows_dir / "deploy.yaml").is_file(), manifest),
        ]
        return found

    def _secrets(self, repo: Repo, found: list[Check]) -> dict[str, Any] | None:
        files = secret_files(repo.secrets_dir)
        found.append(
            rules.check_sops_metadata({str(path.relative_to(repo.root)): is_encrypted(path) for path in files})
        )
        yaml_files = [path for path in files if path.suffix in YAML_SUFFIXES]
        failures: dict[str, str] = {}
        overlay: dict[str, Any] | None = None

        def one(path: Path) -> tuple[Path, bytes | None, AstrariumError | None]:
            try:
                return (
                    path,
                    self.app.sops.decrypt(path),
                    None,
                )
            except AstrariumError as e:
                return (
                    path,
                    None,
                    e,
                )

        for path, plaintext, e in run_pool(one, yaml_files):
            if e is not None or plaintext is None:
                failures[str(path.relative_to(repo.root))] = e.message if e is not None else "no plaintext"
                continue
            if path == repo.overlay:
                data = yaml.safe_load(plaintext)
                overlay = data if isinstance(data, dict) else {}
        if not repo.overlay.is_file():
            failures[str(repo.overlay.relative_to(repo.root))] = "missing"
        found.append(rules.check_decryptable(failures, len(yaml_files)))
        return overlay

    def _manifest(self, repo: Repo, overlay: dict[str, Any] | None, found: list[Check]) -> Manifest | None:
        try:
            found.append(rules.check_plaintext_secrets(read_raw(repo.manifest)))
            manifest = load_manifest(repo, overlay)
        except AstrariumError as e:
            found.append(
                Check(
                    "manifest",
                    "fail",
                    e.message,
                    e.hint,
                )
            )
            return None
        found += [
            Check(
                "manifest",
                "pass",
                f"{len(manifest.nodes)} nodes",
            ),
            rules.check_domain(manifest),
        ]
        return manifest

    def _topology(
        self,
        repo: Repo,
        overlay: dict[str, Any] | None,
        found: list[Check],
    ) -> tuple[HexRiftApp, dict[str, HexRiftNode]] | None:
        try:
            found.append(rules.check_namespace(topology_namespace(repo.topology), overlay_namespace(overlay or {})))
            app = open_hexrift(repo.topology)
        except AstrariumError as e:
            found.append(
                Check(
                    "topology",
                    "fail",
                    e.message,
                    e.hint,
                )
            )
            return None
        hexrift = hexrift_nodes(app)
        found.append(
            Check(
                "topology",
                "pass",
                f"{len(hexrift)} hub/exit nodes",
            )
        )
        return app, hexrift

    def _nodes(
        self,
        manifest: Manifest,
        hexrift: dict[str, HexRiftNode],
        found: list[Check],
    ) -> dict[str, EffectiveNode] | None:
        try:
            nodes = effective_nodes(manifest, {node_id: node.region for node_id, node in hexrift.items()})
        except AstrariumError as e:
            found.append(
                Check(
                    "nullforge validation",
                    "fail",
                    e.message,
                    e.hint,
                )
            )
            return None
        found.append(
            Check(
                "nullforge validation",
                "pass",
                f"{len(nodes)} nodes",
            )
        )
        return nodes

    def _haproxy(
        self,
        repo: Repo,
        app: HexRiftApp,
        nodes: dict[str, EffectiveNode],
        hexrift: dict[str, HexRiftNode],
    ) -> Check:
        """Key files missing -> warn (not checked), HexRift build error -> fail."""

        store = KeyStore(repo, self.app.sops)
        ids = sorted(node_id for node_id in hexrift if node_id in nodes)
        if store.missing(ids):
            return Check(
                "haproxy",
                "warn",
                "not checked: key files missing",
            )
        try:
            with RuntimeDir() as runtime:
                built = build_nodes(
                    app,
                    ids,
                    store.decrypt_all(runtime.sub("keys")),
                    runtime.sub("build"),
                )
                return rules.check_haproxy(nodes, built)
        except AstrariumError as e:
            return Check(
                "haproxy",
                "fail",
                e.message,
                e.hint,
            )

    def _lockfile(self, repo: Repo) -> Check:
        if not repo.pyproject.is_file() or not repo.lockfile.is_file():
            return Check(
                "uv.lock sources",
                "fail",
                "pyproject.toml or uv.lock missing",
                "the deployment repo pins its tool stack",
            )
        return rules.check_lockfile(
            repo.pyproject.read_text(encoding="utf-8"), repo.lockfile.read_text(encoding="utf-8")
        )

    def _dns(self, repo: Repo, manifest: Manifest, nodes: dict[str, EffectiveNode]) -> list[Check]:
        domain = manifest.deployment.domain
        if not repo.dns_dir.is_dir() or domain is None:
            return []
        zone_file: Path = repo.dns_dir / "zones" / f"{domain}.yaml"
        name = str(zone_file.relative_to(repo.root))
        if not zone_file.is_file():
            return [
                Check(
                    "dns records",
                    "fail",
                    f"{name} missing",
                )
            ]
        try:
            return rules.check_dns(
                read_raw(zone_file),
                domain,
                nodes,
                ignored=dns_ignored_names(zone_file),
            )
        except AstrariumError as e:
            return [
                Check(
                    "dns records",
                    "fail",
                    e.message,
                    e.hint,
                )
            ]
        except (
            AttributeError,
            TypeError,
            ValueError,
        ) as e:
            return [
                Check(
                    "dns records",
                    "fail",
                    f"{name}: unexpected record shape ({type(e).__name__})",
                )
            ]

    def _reality_dest(self, repo: Repo) -> Check:
        """`git show HEAD:topology.yaml` failure -> warn, not compared."""

        committed = _committed_topology(repo)
        if committed is None:
            return Check(
                "reality dest",
                "warn",
                "not compared",
                "run `git show HEAD:topology.yaml` to see why",
            )
        return rules.check_reality_dest(committed, read_raw(repo.topology))
