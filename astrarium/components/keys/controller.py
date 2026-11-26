"""HexRift key files: local generation and decrypted view."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import yaml

from astrarium.components.secrets.keystore import KeyStore
from astrarium.components.topology.bridge import gen_keys
from astrarium.core import BaseController
from astrarium.errors import UsageProblem
from astrarium.runtime import RuntimeDir


if TYPE_CHECKING:
    from astrarium.app import AstrariumApp


class KeysController(BaseController["AstrariumApp"]):
    """Only place creating key files, never rotates existing ones."""

    def gen(self, node_ids: list[str]) -> list[str]:
        """Create key files for `node_ids` (default: every hub/exit) that lack one, return created ids."""

        repo = self.app.repo
        store = KeyStore(repo, self.app.sops)
        with RuntimeDir() as runtime:
            ctx = self.app.topology.prepare(runtime, need_keys=True)
            unknown = sorted(set(node_ids) - set(ctx.hexrift))
            if unknown:
                raise UsageProblem(f"not hub/exit nodes of topology.yaml: {', '.join(unknown)}")
            keys_dir = ctx.keys_dir
            if keys_dir is None:
                raise RuntimeError("prepare(need_keys=True) returned no keys dir")
            created = gen_keys(
                ctx.app,
                store.missing(node_ids or sorted(ctx.hexrift)),
                keys_dir,
            )
            for node_id in created:
                store.store(node_id, keys_dir / f"{node_id}.yaml")
        return created

    def show(self, node_id: str) -> dict[str, Any]:
        """Decrypted key file of `node_id`."""

        path = self.app.repo.key_file(node_id)
        if not path.is_file():
            raise UsageProblem(f"no key file for {node_id}", hint="run `arium keys gen` first")
        data = yaml.safe_load(self.app.sops.decrypt(path))
        return data if isinstance(data, dict) else {}
