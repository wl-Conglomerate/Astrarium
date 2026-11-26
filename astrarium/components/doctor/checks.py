"""Doctor rules: pure functions over parsed repo data, one Check each."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import sys
import tomllib
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from astrarium.components.manifest.derive import EffectiveNode
from astrarium.components.manifest.layering import get_path
from astrarium.components.manifest.models import Manifest
from astrarium.components.manifest.overlay import sensitive_feature_paths
from astrarium.components.topology.bridge import NAMESPACE_PLACEHOLDER, BuiltNode, HexRiftNode
from astrarium.components.topology.controller import consistency_problems


Status = Literal["pass", "warn", "fail"]

REQUIRED_TOOLS = (
    "git",
    "ssh",
    "sops",
    "uv",
)

PHOTON_ENV = ("UV_INDEX_PHOTON_USERNAME", "UV_INDEX_PHOTON_PASSWORD")

PHOTON_PACKAGES = (
    "astrarium",
    "hexrift",
    "nullforge",
    "manticora",
)

SSHFP_ALGORITHMS = {
    "rsa": 1,
    "ecdsa": 3,
    "ed25519": 4,
}

SSHFP_DIGESTS: dict[int, Callable[[bytes], str]] = {
    1: lambda blob: hashlib.sha1(blob, usedforsecurity=False).hexdigest(),
    2: lambda blob: hashlib.sha256(blob).hexdigest(),
}

DNS_IGNORE_MARKER = "astrarium:ignore"
"""Comment marker on a zone record name
(`status:  # astrarium:ignore`) marking it intentionally not a node."""


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _values(record: Mapping[str, Any]) -> list[Any]:
    return list(record["values"]) if "values" in record else [record.get("value")]


@dataclass(frozen=True)
class Check:
    name: str
    status: Status
    detail: str
    hint: str | None = None


def _verdict(name: str, problems: list[str], ok: str, hint: str | None, status: Status = "fail") -> Check:
    if problems:
        return Check(
            name,
            status,
            "; ".join(problems),
            hint,
        )
    return Check(
        name,
        "pass",
        ok,
    )


def check_tools(which: Callable[[str], str | None]) -> list[Check]:
    """Python version and external tools on PATH."""

    checks = [
        Check(
            "python",
            "pass" if sys.version_info >= (3, 13) else "fail",
            sys.version.split()[0],
            "Python >= 3.13",
        )
    ]
    for tool in REQUIRED_TOOLS:
        found = which(tool)
        checks.append(
            Check(
                f"tool {tool}",
                "pass" if found else "fail",
                found or "not on PATH",
                None if found else f"install {tool}",
            )
        )
    return checks


def check_environment(env: Mapping[str, str]) -> list[Check]:
    """Photon credentials (needed by uv for bumps and syncs) and optional GitHub token."""

    missing = [name for name in PHOTON_ENV if not env.get(name)]
    photon = Check(
        "photon credentials",
        "warn" if missing else "pass",
        f"{', '.join(missing)} not set" if missing else "set",
        "UV_INDEX_PHOTON_USERNAME=__token__ and UV_INDEX_PHOTON_PASSWORD=<read token>" if missing else None,
    )
    token = "set" if env.get("GITHUB_TOKEN") else "not set (GitHub API limit 60 requests/hour)"
    return [
        photon,
        Check(
            "github token",
            "pass",
            token,
        ),
    ]


def check_leftovers(paths: Iterable[Path]) -> Check:
    """Runtime dirs left by killed runs (RuntimeDir's own base dir, may hold decrypted secrets)."""

    found = [str(path) for path in paths]
    return _verdict(
        "runtime leftovers",
        found,
        "none",
        "remove them with `rm -rf` (they may hold decrypted keys)",
        "warn",
    )


def check_sops_metadata(files: Mapping[str, bool]) -> Check:
    """Every file under secrets/ (`.gitkeep` aside) is `.yaml`/`.yml` with sops metadata."""

    plain = sorted(name for name, encrypted in files.items() if not encrypted)
    return _verdict(
        "secrets encrypted",
        plain,
        f"{len(files)} files",
        "encrypt with sops; plaintext must never be committed",
    )


def check_decryptable(failures: Mapping[str, str], total: int) -> Check:
    """Current identity decrypts every file under secrets/."""

    problems = [f"{name}: {reason}" for name, reason in sorted(failures.items())]
    return _verdict(
        "secrets decryptable",
        problems,
        f"{total} files",
        "your age identity must be a recipient in .sops.yaml",
    )


def check_plaintext_secrets(raw: Mapping[str, Any]) -> Check:
    """astrarium.yaml sets no value NullForge marks sensitive (those belong in overlay)."""

    found: list[str] = []
    places: list[tuple[str, Any]] = [("features", raw.get("features", {}))]
    places += [
        (f"roles.{name}.features", _mapping(spec).get("features", {}))
        for name, spec in _mapping(raw.get("roles", {})).items()
    ]
    places += [
        (f"nodes.{name}.overrides.features", _mapping(_mapping(spec).get("overrides", {})).get("features", {}))
        for name, spec in _mapping(raw.get("nodes", {})).items()
    ]
    for prefix, features in places:
        for path in sorted(sensitive_feature_paths()):
            try:
                value = get_path(_mapping(features), path)
            except KeyError:
                continue
            if value not in (
                None,
                "",
                {},
                [],
            ):
                found.append(f"{prefix}.{path}")
    return _verdict(
        "no plaintext secrets",
        found,
        "none in astrarium.yaml",
        "move them to secrets/astrarium.sops.yaml",
    )


def check_domain(manifest: Manifest) -> Check:
    """IP-only deployments are refused until HexRift dials exits by hostname."""

    if manifest.deployment.domain:
        return Check(
            "domain",
            "pass",
            manifest.deployment.domain,
        )
    return Check(
        "domain",
        "fail",
        "deployment.domain missing",
        "IP-only deployments need a HexRift release with hostname-based exit links",
    )


def check_namespace(topology_namespace: str | None, overlay_namespace: str | None) -> Check:
    """topology.yaml holds placeholder, overlay holds real namespace."""

    problems = []
    if topology_namespace != NAMESPACE_PLACEHOLDER:
        problems.append(f"topology.yaml global.namespace is not {NAMESPACE_PLACEHOLDER!r}")
    if not overlay_namespace or overlay_namespace == NAMESPACE_PLACEHOLDER:
        problems.append("overlay topology.namespace missing")
    return _verdict(
        "namespace",
        problems,
        "placeholder in topology, real value in overlay",
        "the namespace seeds every client UUID: keep it in the overlay only",
    )


def check_node_sets(
    manifest: Manifest,
    nodes: Mapping[str, EffectiveNode],
    hexrift: Mapping[str, HexRiftNode],
) -> Check:
    """Hub/exit sets match between manifest and topology, root roles match region types."""

    problems = consistency_problems(
        manifest,
        nodes,
        hexrift,
    )
    return _verdict(
        "hub/exit nodes",
        problems,
        f"{len(hexrift)} in both files",
        "add or remove nodes in both astrarium.yaml and topology.yaml",
    )


def check_key_files(nodes: Mapping[str, EffectiveNode], key_ids: set[str]) -> Check:
    """Every hub/exit node has secrets/keys/<id>.yaml."""

    missing = sorted(node_id for node_id, node in nodes.items() if node.is_hexrift and node_id not in key_ids)
    return _verdict(
        "key files",
        missing,
        "every hub/exit node",
        "run `arium keys gen` and commit secrets/keys/",
    )


def check_host_keys(nodes: Mapping[str, EffectiveNode]) -> Check:
    """Every node carries its SSH host key (trust anchor)."""

    missing = sorted(node_id for node_id, node in nodes.items() if not node.host_keys)
    return _verdict(
        "host keys",
        missing,
        "every node",
        "add nodes.<id>.host_keys from a verified source",
    )


def check_hostnames(
    manifest: Manifest,
    nodes: Mapping[str, EffectiveNode],
    hexrift: Mapping[str, HexRiftNode],
    aphelion_domain: str,
) -> Check:
    """Topology hostnames equal derived FQDNs, global.aphelion_domain is <names.exit>.<domain>."""

    problems = [
        f"{node_id}: topology {node.hostname} != derived {nodes[node_id].fqdn}"
        for node_id, node in sorted(hexrift.items())
        if node_id in nodes and (nodes[node_id].fqdn or "").lower() != node.hostname.lower()
    ]
    exit_label, domain = manifest.deployment.names.get("exit"), manifest.deployment.domain
    expected = f"{exit_label}.{domain}" if exit_label and domain else None
    if expected is None or expected.lower() != aphelion_domain.lower():
        problems.append(f"global.aphelion_domain {aphelion_domain} != {expected or '<names.exit>.<domain>'}")
    return _verdict(
        "hostnames",
        problems,
        "topology matches derived names",
        "set nodes.<id>.fqdn or fix topology.yaml hostnames",
    )


def _port_matches(port: int | str | None, ssh_port: int) -> bool:
    """FirewallRule.port covers ssh_port: None means every port, "N:M" ranges, else exact match."""

    if port is None:
        return True
    low, _, high = str(port).partition(":")
    try:
        return int(low) <= ssh_port <= int(high or low)
    except ValueError:
        return False


def _ssh_allowed(node: EffectiveNode) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network] | Literal["any"]:
    """Source networks allowed at node's SSH port, "any" when matching rule has no from_ip filter.

    Rule counts when its action is `allow` or `limit` (UFW still lets connections through,
    only rate-limiting them), its proto is not `udp`, its direction is not `out`, and its port
    covers ssh_port. `from_ip` of None, empty, "any" or "anywhere" means any source.
    """

    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for rule in node.features["netsec"]["firewall_rules"]:
        if rule.get("action") not in ("allow", "limit"):
            continue
        if rule.get("proto") == "udp" or rule.get("direction") == "out":
            continue
        if not _port_matches(rule.get("port"), node.ssh_port):
            continue
        from_ip = rule.get("from_ip")
        if from_ip in (
            None,
            "",
            "any",
            "anywhere",
        ):
            return "any"
        try:
            networks.append(ipaddress.ip_network(from_ip, strict=False))
        except ValueError:
            continue
    return networks


def check_jump(manifest: Manifest, nodes: Mapping[str, EffectiveNode]) -> Check:
    """control.jump has host keys and every non-bastion firewall allows its addresses."""

    jump_id = manifest.control.jump
    if jump_id is None:
        return Check(
            "jump",
            "pass",
            "no jump host (direct SSH only)",
        )
    if jump_id not in nodes:
        return Check(
            "jump",
            "warn",
            f"{jump_id} not in fleet yet",
            "add it to astrarium.yaml nodes",
        )
    jump = nodes[jump_id]
    problems = [] if jump.host_keys else [f"{jump_id} has no host_keys"]
    addresses = [ipaddress.ip_address(a) for a in (jump.ipv4, jump.ipv6) if a is not None]
    for node_id, node in sorted(nodes.items()):
        if node.root_role == "bastion":
            continue
        allowed = _ssh_allowed(node)
        if allowed == "any":
            continue
        blocked = [str(a) for a in addresses if not any(a in network for network in allowed)]
        if blocked:
            problems.append(f"{node_id} firewall does not allow {', '.join(blocked)}")
    return _verdict(
        "jump",
        problems,
        f"{jump_id} allowed on every node",
        "keep the jump node in astrarium.yaml with host_keys",
    )


def check_ssh_sources(nodes: Mapping[str, EffectiveNode]) -> Check:
    """Every firewalled non-bastion node allows SSH from some source (else UFW locks SSH out)."""

    locked = sorted(
        node_id
        for node_id, node in nodes.items()
        if node.root_role != "bastion" and node.features["netsec"]["firewall"] and _ssh_allowed(node) == []
    )
    return _verdict(
        "ssh sources",
        locked,
        "every firewalled node allows SSH",
        "add control.ssh_allow entries or control.jump",
    )


def check_haproxy(nodes: Mapping[str, EffectiveNode], built: Mapping[str, BuiltNode]) -> Check:
    """HexRift renders HAProxy only where NullForge installs it."""

    missing = sorted(
        node_id
        for node_id, node in built.items()
        if node.haproxy_wanted and not nodes[node_id].features["haproxy"]["install"]
    )
    return _verdict(
        "haproxy",
        missing,
        "rendered HAProxy only where installed",
        "set features.haproxy.install: true or disable HAProxy in topology.yaml",
    )


def check_lockfile(pyproject_text: str, lock_text: str) -> Check:
    """uv.lock resolves every photon-only package from photon index."""

    try:
        indexes = tomllib.loads(pyproject_text).get("tool", {}).get("uv", {}).get("index", [])
        packages = tomllib.loads(lock_text).get("package", [])
    except tomllib.TOMLDecodeError as e:
        return Check(
            "uv.lock sources",
            "fail",
            f"cannot parse TOML: {e}",
        )
    photon = next((index.get("url", "") for index in indexes if index.get("name") == "photon"), None)
    if photon is None:
        return Check(
            "uv.lock sources",
            "fail",
            "pyproject.toml has no [[tool.uv.index]] named photon",
        )
    problems = [
        f"{package['name']} from {_mapping(package.get('source', {})).get('registry', 'a non-registry source')}"
        for package in packages
        if package.get("name") in PHOTON_PACKAGES
        and _mapping(package.get("source", {})).get("registry", "").rstrip("/") != photon.rstrip("/")
    ]
    return _verdict(
        "uv.lock sources",
        problems,
        "photon packages resolve from photon",
        'add [tool.uv.sources] <pkg> = { index = "photon" } and run `uv lock`',
    )


def _records(zone: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    found: dict[str, list[dict[str, Any]]] = {}
    for name, value in zone.items():
        entries = value if isinstance(value, list) else [value]
        found[str(name).lower()] = [entry for entry in entries if isinstance(entry, dict)]
    return found


def sshfp_fingerprint(blob: str, fingerprint_type: int) -> str | None:
    """SSHFP fingerprint of base64 host key blob, None for unknown digest type."""

    digest = SSHFP_DIGESTS.get(fingerprint_type)
    return digest(base64.b64decode(blob)) if digest is not None else None


def check_dns(
    zone: Mapping[str, Any],
    domain: str,
    nodes: Mapping[str, EffectiveNode],
    *,
    ignored: Iterable[str] = (),
) -> list[Check]:
    """A/AAAA per node and SSHFP matching host_keys (fail), names that are no node (warn).

    `ignored` holds record names marked with DNS_IGNORE_MARKER in zone file: intentional
    non-node names (services, CNAMEs), not warned about.
    """

    records = _records(zone)
    suffix = f".{domain.lower()}"
    problems: list[str] = []
    node_names: set[str] = set()
    for node_id, node in sorted(nodes.items()):
        fqdn = (node.fqdn or "").lower()
        if not fqdn.endswith(suffix):
            problems.append(f"{node_id}: {fqdn or 'no fqdn'} outside zone {domain}")
            continue
        name = fqdn.removesuffix(suffix)
        node_names.add(name)
        by_type = {record.get("type"): record for record in records.get(name, [])}
        for rtype, address in (("A", node.ipv4), ("AAAA", node.ipv6)):
            if address is None:
                continue
            if rtype not in by_type:
                problems.append(f"{node_id}: no {rtype} record")
            elif str(address) not in {str(value) for value in _values(by_type[rtype])}:
                problems.append(f"{node_id}: {rtype} record does not point at {address}")
        if "SSHFP" in by_type:
            problems += _sshfp_problems(
                node_id,
                node,
                _values(by_type["SSHFP"]),
            )
    skip = set(ignored)
    extra = sorted(
        name
        for name in records
        if name not in node_names and name not in skip and name and not name.startswith(("_", "*"))
    )
    return [
        _verdict(
            "dns records",
            problems,
            "every node resolves, SSHFP matches host_keys",
            "fix dns/zones or astrarium.yaml addresses",
        ),
        _verdict(
            "dns extra names",
            [f"{name}{suffix}" for name in extra],
            "none",
            f"names that are not nodes: remove them, or mark the name `# {DNS_IGNORE_MARKER}` in the zone file",
            "warn",
        ),
    ]


def _sshfp_problems(node_id: str, node: EffectiveNode, values: list[Any]) -> list[str]:
    problems = []
    by_algorithm = {SSHFP_ALGORITHMS[kind]: blob for kind, blob in node.host_keys.items()}
    for value in values:
        entry = _mapping(value)
        algorithm, fp_type = entry.get("algorithm"), entry.get("fingerprint_type")
        blob = by_algorithm.get(algorithm) if isinstance(algorithm, int) else None
        expected = sshfp_fingerprint(blob, fp_type) if blob is not None and isinstance(fp_type, int) else None
        if expected is None or expected != str(entry.get("fingerprint", "")).lower():
            problems.append(f"{node_id}: SSHFP {algorithm} {fp_type} does not match host_keys")
    return problems


def hub_reality_dests(topology: Mapping[str, Any]) -> dict[str, set[str]]:
    """Effective REALITY dests per hub region of raw topology dict."""

    default = _mapping(
        _mapping(_mapping(_mapping(topology.get("defaults", {})).get("hub", {})).get("reality", {}))
    ).get("dest")
    found: dict[str, set[str]] = {}
    for region in topology.get("regions", []):
        region = _mapping(region)
        if region.get("type") != "hub":
            continue
        base = None if region.get("tls") is not None else _mapping(region.get("reality", {})).get("dest", default)
        dests = {_mapping(_mapping(node).get("reality", {})).get("dest", base) for node in region.get("nodes", [])}
        found[str(region.get("id"))] = {dest for dest in dests if dest}
    return found


def check_reality_dest(committed: Mapping[str, Any] | None, working: Mapping[str, Any]) -> Check:
    """Hub regions whose REALITY dest changed in working tree: clients need new configs (warn)."""

    if committed is None:
        return Check(
            "reality dest",
            "warn",
            "not compared",
            "no committed topology.yaml to compare with",
        )
    before, after = hub_reality_dests(committed), hub_reality_dests(working)
    changed = sorted(region for region in after if region in before and before[region] != after[region])
    return _verdict(
        "reality dest",
        changed,
        "unchanged",
        "clients of these hub regions need new configs; plan a hub key rotation",
        "warn",
    )


def check_deploy_workflow(workflow_present: bool, manifest: Manifest) -> Check:
    """CI deploys without control.jump reach nodes directly, but runner IPs are not allow-listed (warn)."""

    if workflow_present and manifest.control.jump is None:
        return Check(
            "deploy workflow",
            "warn",
            "deploy.yaml present without control.jump",
            "set control.jump: CI reaches nodes through the jump host",
        )
    return Check(
        "deploy workflow",
        "pass",
        "ok",
    )
