"""Manifest models: `astrarium.yaml` merged with decrypted overlay."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Mapping
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from astrarium.components.manifest.keylines import key_identity


Arch = Literal["x86_64", "aarch64"]

ARCH_BY_MACHINE: Mapping[str, Arch] = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
}
"""platform.machine()/uname -m -> manifest Arch, shared by check and integration harness."""

Identity = Literal["deploy", "admin", "ci", "root"]
"""root is first-deploy only: the cast's users/netsec hardening disables it afterwards."""

NODE_ID_PATTERN = r"^[A-Za-z][A-Za-z0-9-]*$"
"""Node ids: no dots, slashes or fnmatch metacharacters (inventory host names, ssh_config aliases)."""

ROLE_PATTERN = r"^[a-z][a-z0-9-]*$"

LABEL_PATTERN = r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$"

USER_PATTERN = r"^[a-z_][a-z0-9_-]*$"

XRAY_MAIN_PATTERN = r"^main@[0-9a-f]{40}$"

RUNE_NAME_PATTERN = r"[a-z][a-z0-9_]*"
"""Bare rune name shape, checked with fullmatch (inventory/runes.py reuses this, no ^/$ needed)."""

HEXRIFT_ROLES = frozenset({"exit", "hub"})

BUILTIN_ROLES = (
    "exit",
    "hub",
    "pulsar",
    "bastion",
)

NodeId = Annotated[str, Field(pattern=NODE_ID_PATTERN)]

RoleName = Annotated[str, Field(pattern=ROLE_PATTERN)]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DeploymentSection(Strict):
    name: str = Field(pattern=r"^[a-z0-9-]+$", description="Deployment name: run ids, notifications.")
    domain: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9.-]+$",
        description="Fleet domain.",
    )
    names: dict[RoleName, Annotated[str, Field(pattern=LABEL_PATTERN)]] = Field(
        default_factory=dict, description="Root role -> DNS label under domain."
    )


class SshAllow(Strict):
    source: str = Field(description="IPv4/IPv6 address or network, kept verbatim as firewall from_ip.")
    comment: str | None = Field(default=None, description="Firewall rule comment, kept verbatim.")


class CiControl(Strict):
    cast_user: str = Field(
        default="astrarium_ci",
        pattern=USER_PATTERN,
        max_length=32,
    )
    cast_keys: list[str] = Field(default_factory=list)


class OrreryControl(Strict):
    host: str
    topology_path: str


class ControlSection(Strict):
    deploy_user: str = Field(
        default="github_actions",
        pattern=USER_PATTERN,
        max_length=32,
    )
    deploy_keys: list[str] = Field(default_factory=list, description="authorized_keys lines, options preserved.")
    ci: CiControl | None = None
    jump: str | None = Field(default=None, description="Node id of the SSH jump host.")
    ssh_allow: list[str | SshAllow] = Field(default_factory=list)
    orrery: OrreryControl | None = None

    @model_validator(mode="after")
    def _ci_cast_user_distinct_from_deploy_user(self) -> ControlSection:
        """deploy_access and ci_access runes would both write /etc/sudoers.d/<user> and authorized_keys."""

        if self.ci is not None and self.ci.cast_user == self.deploy_user:
            raise ValueError("control.ci.cast_user must differ from control.deploy_user")
        return self

    @model_validator(mode="after")
    def _ci_cast_keys_distinct_from_deploy_keys(self) -> ControlSection:
        """Key in both lists stays deploy login after CI revoke, compared by type and blob."""

        if self.ci is None:
            return self
        deploy = {key_identity(line) for line in self.deploy_keys} - {None}
        if any(key_identity(line) in deploy for line in self.ci.cast_keys):
            raise ValueError("control.ci.cast_keys must not repeat a control.deploy_keys key")
        return self


class DiscordNotify(Strict):
    webhook_url: str | None = None
    thread_id: str | None = None

    @field_validator("thread_id", mode="before")
    @classmethod
    def _numeric_thread_id(cls, value: Any) -> Any:
        return str(value) if isinstance(value, int) and not isinstance(value, bool) else value


class NotifySection(Strict):
    discord: DiscordNotify | None = None


class KeysSection(Strict):
    exit_rotation: Literal["manual", "full-deploy"] = "manual"


class RoleSpec(Strict):
    extends: str | None = None
    system: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, Any] = Field(default_factory=dict)
    runes: list[str] = Field(default_factory=list)

    @field_validator("runes")
    @classmethod
    def _rune_names_are_bare(cls, value: list[str]) -> list[str]:
        for name in value:
            if not re.fullmatch(RUNE_NAME_PATTERN, name):
                raise ValueError(f"rune name {name!r} must match [a-z][a-z0-9_]*")
        return value


class XrayRelease(Strict):
    version: str = Field(pattern=r"^v\d+\.\d+\.\d+$")
    sha256: dict[Arch, Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]]


VersionPin = str | XrayRelease
"""Component pin: version string, xray release `{version, sha256}` or xray `main@<40 hex>`."""


class NodeSsh(Strict):
    port: int = Field(
        default=22,
        ge=1,
        le=65535,
    )
    user: str | None = Field(
        default=None,
        pattern=USER_PATTERN,
        max_length=32,
    )


class NodeOverrides(Strict):
    system: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, Any] = Field(default_factory=dict)
    versions: dict[str, VersionPin] = Field(default_factory=dict)


class NodeSpec(Strict):
    role: str
    ipv4: IPv4Address
    ipv6: IPv6Address | None = None
    arch: Arch = "x86_64"
    region: str | None = Field(default=None, pattern=r"^[a-z0-9-]+$")
    hostname: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.-]+$")
    fqdn: str | None = Field(default=None, pattern=r"^[A-Za-z0-9.-]+$")
    ssh: NodeSsh = Field(default_factory=NodeSsh)
    host_keys: dict[Literal["ed25519", "ecdsa", "rsa"], str] = Field(default_factory=dict)
    overrides: NodeOverrides = Field(default_factory=NodeOverrides)

    @field_validator("host_keys")
    @classmethod
    def _base64_blobs(cls, value: dict[str, str]) -> dict[str, str]:
        for kind, blob in value.items():
            if not blob:
                raise ValueError(f"host_keys.{kind} must not be empty")
            try:
                base64.b64decode(blob, validate=True)
            except (binascii.Error, ValueError) as e:
                raise ValueError(f"host_keys.{kind} must be the base64 key blob (second field of the key line)") from e
        return value


class ComponentSpec(Strict):
    owner: Literal["nullforge"]
    upstream: str
    binary: str
    probe: str | None = None
    rune: str
    feature: str


class Manifest(Strict):
    deployment: DeploymentSection
    control: ControlSection = Field(default_factory=ControlSection)
    notify: NotifySection = Field(default_factory=NotifySection)
    keys: KeysSection = Field(default_factory=KeysSection)
    system: dict[str, Any] = Field(default_factory=dict)
    features: dict[str, Any] = Field(default_factory=dict)
    roles: dict[RoleName, RoleSpec] = Field(default_factory=dict)
    versions: dict[str, VersionPin] = Field(default_factory=dict)
    components: dict[str, ComponentSpec] = Field(default_factory=dict)
    nodes: dict[NodeId, NodeSpec]

    @model_validator(mode="after")
    def _references(self) -> Manifest:
        problems = [
            *self._role_problems(),
            *self._reference_problems(),
            *self._pin_problems(),
        ]
        if problems:
            raise ValueError("; ".join(problems))
        return self

    def _role_problems(self) -> list[str]:
        known = set(BUILTIN_ROLES) | set(self.roles)
        problems = [
            f"nodes.{nid}.role: unknown role {n.role!r}" for nid, n in self.nodes.items() if n.role not in known
        ]
        for name, spec in self.roles.items():
            if name not in BUILTIN_ROLES and spec.extends is None:
                problems.append(f"roles.{name}: custom role needs extends")
            if spec.extends is not None and spec.extends not in known:
                problems.append(f"roles.{name}.extends: unknown role {spec.extends!r}")
        return problems

    def _reference_problems(self) -> list[str]:
        refs: dict[str, str | None] = {}
        if self.nodes:
            refs["control.jump"] = self.control.jump
        if self.control.orrery is not None:
            refs["control.orrery.host"] = self.control.orrery.host
        return [
            f"{where}: {ref!r} is not a node id"
            for where, ref in refs.items()
            if ref is not None and ref not in self.nodes
        ]

    def _pin_problems(self) -> list[str]:
        layers = [("versions", self.versions)]
        layers += [(f"nodes.{nid}.overrides.versions", n.overrides.versions) for nid, n in self.nodes.items()]
        problems: list[str] = []
        for where, pins in layers:
            for component, pin in pins.items():
                if component == "xray" and isinstance(pin, str) and not re.fullmatch(XRAY_MAIN_PATTERN, pin):
                    problems.append(f"{where}.xray: string pin must be main@<40 hex>, releases use {{version, sha256}}")
                if component != "xray" and isinstance(pin, XrayRelease):
                    problems.append(f"{where}.{component}: only xray takes a {{version, sha256}} pin")
        return problems
