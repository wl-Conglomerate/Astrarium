"""Check report: node diffs, secrets and version changes, markdown for PR comments."""

from __future__ import annotations

import difflib
import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from pydantic import ValidationError
from rich.table import Table

from astrarium.components.check.runners import CheckResult
from astrarium.components.manifest.models import VersionPin, XrayRelease
from astrarium.components.rollout.artifacts import pin_label as _artifact_pin_label
from astrarium.components.secrets.masking import ValueMasker, mask_haproxy, mask_structure
from astrarium.components.topology.bridge import BuiltNode
from astrarium.components.versions.registry import lock_versions


MARKER = "<!-- astrarium-check -->"
"""First line of every report, sticky PR comment finds itself by it."""

COMMENT_LIMIT = 60_000
"""Below GitHub comment body limit (65536), room left for workflow framing."""

FENCE = "````"

OMISSION_NOTE = (
    "\n{count} detail section(s) omitted to fit comment size, run `arium repo check` locally for all of them.\n"
)

TRUNCATION_NOTE = "\n\n(report truncated to fit comment size limit)\n"

KEYS_DIR = "secrets/keys"

REASON_LINE = re.compile(r"Failed to start|\[ALERT\]")
"""xray start failure or haproxy alert: line naming why test failed."""

NodeState = Literal["added", "removed", "changed", "unchanged"]

ReportStatus = Literal["passed", "failed", "skipped"]


def _masked_haproxy(built: BuiltNode | None, masker: ValueMasker) -> str:
    return "" if built is None else masker.mask(mask_haproxy(built.haproxy_cfg.read_text()))


def _set_change(before: set[str], after: set[str]) -> SetChange:
    return SetChange(added=sorted(after - before), removed=sorted(before - after))


def secrets_file_changes(
    base_files: Mapping[str, Mapping[str, Any]], head_files: Mapping[str, Mapping[str, Any]]
) -> list[SecretsFileChange]:
    return [
        SecretsFileChange(name, _key_node(name))
        for name in sorted(base_files.keys() & head_files.keys())
        if _sealed(base_files[name]) != _sealed(head_files[name])
    ]


def _changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> list[VersionChange]:
    return [
        VersionChange(
            path,
            _pin_label(before[path]) if path in before else None,
            _pin_label(after[path]) if path in after else None,
        )
        for path in sorted(before.keys() | after.keys())
        if before.get(path) != after.get(path)
    ]


def version_changes(base_raw: Mapping[str, Any], head_raw: Mapping[str, Any]) -> list[VersionChange]:
    return _changes(_pins(base_raw), _pins(head_raw))


def tool_stack_changes(base_lock: str, head_lock: str) -> list[VersionChange]:
    return _changes(lock_versions(base_lock), lock_versions(head_lock))


def renderer_warning(changes: list[VersionChange]) -> list[str]:
    return [
        f"uv.lock moves HexRift {change.before} -> {change.after}: base and head were rendered with head HexRift, "
        "so diffs exclude renderer changes, run `arium fleet deploy --dry-run` to see them"
        for change in changes
        if change.path == "hexrift"
    ]


def _code_list(items: list[str]) -> str:
    return ", ".join(f"`{item}`" for item in items)


def _status(result: CheckResult | None) -> str:
    return "-" if result is None else result.status


def report_json(report: CheckReport) -> dict[str, Any]:
    return {**asdict(report), "failed": report.failed}


@dataclass(frozen=True)
class NodeDiff:
    """Change of one node's rendered files, diffs masked."""

    node_id: str
    state: NodeState
    config_diff: str = ""
    haproxy_diff: str = ""


@dataclass(frozen=True)
class PathChanges:
    """Dotted overlay paths added, removed or re-encrypted."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    changed: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class SetChange:
    """Members added and removed."""

    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RecipientChanges:
    """Recipient changes in .sops.yaml and in sops metadata of each secrets file."""

    config: SetChange = field(default_factory=SetChange)
    files: dict[str, SetChange] = field(default_factory=dict)


@dataclass(frozen=True)
class SecretsFileChange:
    """Secrets file whose ciphertext or sops mac changed, node set for key files."""

    path: str
    node: str | None = None


@dataclass(frozen=True)
class VersionChange:
    """Pin at dotted manifest path or tool-stack package name, before and after."""

    path: str
    before: str | None
    after: str | None


@dataclass
class CheckReport:
    """Everything check found, `failed` drives exit code."""

    base: str
    head: str
    nodes: list[NodeDiff]
    tests: list[CheckResult]
    versions: list[VersionChange]
    tool_stack: list[VersionChange]
    overlay: PathChanges
    recipients: RecipientChanges
    code_diff: str
    warnings: list[str]
    secrets_files: list[SecretsFileChange] = field(default_factory=list)

    @property
    def failures(self) -> list[CheckResult]:
        return [result for result in self.tests if result.status == "failed"]

    @property
    def failed(self) -> bool:
        return bool(self.failures)

    @property
    def skipped(self) -> list[CheckResult]:
        return [result for result in self.tests if result.status == "skipped"]

    @property
    def status(self) -> ReportStatus:
        """failed on any failure, skipped when no test ran, else passed."""

        if self.failed:
            return "failed"
        return "passed" if any(result.status == "passed" for result in self.tests) else "skipped"


def _masked_config(built: BuiltNode | None, masker: ValueMasker) -> str:
    if built is None:
        return ""
    return masker.mask(json.dumps(mask_structure(json.loads(built.config_json.read_text())), indent=2)) + "\n"


def _unified(before: str, after: str, name: str) -> str:
    lines = difflib.unified_diff(
        before.splitlines(keepends=True),
        after.splitlines(keepends=True),
        fromfile=f"base/{name}",
        tofile=f"head/{name}",
    )
    return "".join(lines)


def diff_nodes(base: Mapping[str, BuiltNode], head: Mapping[str, BuiltNode], masker: ValueMasker) -> list[NodeDiff]:
    """State per node from raw bytes, diffs from masked text."""

    diffs: list[NodeDiff] = []
    for node_id in sorted(set(base) | set(head)):
        before, after = base.get(node_id), head.get(node_id)
        if (
            before is not None
            and after is not None
            and before.config_json.read_bytes() == after.config_json.read_bytes()
            and before.haproxy_cfg.read_bytes() == after.haproxy_cfg.read_bytes()
        ):
            diffs.append(NodeDiff(node_id, "unchanged"))
            continue
        state: NodeState = "added" if before is None else "removed" if after is None else "changed"
        config = _unified(
            _masked_config(before, masker),
            _masked_config(after, masker),
            f"{node_id}/config.json",
        )
        haproxy = _unified(
            _masked_haproxy(before, masker),
            _masked_haproxy(after, masker),
            f"{node_id}/haproxy.cfg",
        )
        diffs.append(
            NodeDiff(
                node_id,
                state,
                config_diff=config,
                haproxy_diff=haproxy,
            )
        )
    return diffs


def _leaf_paths(tree: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    leaves: dict[str, Any] = {}
    for key, value in tree.items():
        path = f"{prefix}{key}"
        if isinstance(value, Mapping):
            leaves.update(_leaf_paths(value, f"{path}."))
        else:
            leaves[path] = value
    return leaves


def overlay_changes(base: Mapping[str, Any], head: Mapping[str, Any]) -> PathChanges:
    """Overlay paths added, removed or with new ciphertext (sops key names stay plaintext)."""

    before = _leaf_paths({key: value for key, value in base.items() if key != "sops"})
    after = _leaf_paths({key: value for key, value in head.items() if key != "sops"})
    return PathChanges(
        added=sorted(after.keys() - before.keys()),
        removed=sorted(before.keys() - after.keys()),
        changed=sorted(path for path in before.keys() & after.keys() if before[path] != after[path]),
    )


def _age_entries(value: Any) -> set[str]:
    items = value.split(",") if isinstance(value, str) else value
    return {str(item).strip() for item in items if str(item).strip()}


def config_recipients(config: Mapping[str, Any]) -> set[str]:
    """age recipients of every .sops.yaml creation rule, plain and key-group forms."""

    found: set[str] = set()
    for rule in config.get("creation_rules", []):
        found |= _age_entries(rule.get("age", []))
        for group in rule.get("key_groups", []):
            found |= _age_entries(group.get("age", []))
    return found


def file_recipients(encrypted: Mapping[str, Any]) -> set[str]:
    """age recipients recorded in sops metadata of one encrypted file."""

    meta = encrypted.get("sops", {})
    entries = list(meta.get("age", []))
    for group in meta.get("key_groups", []):
        entries.extend(group.get("age", []))
    return {entry["recipient"] for entry in entries if "recipient" in entry}


def recipient_changes(
    base_config: Mapping[str, Any],
    head_config: Mapping[str, Any],
    base_files: Mapping[str, Mapping[str, Any]],
    head_files: Mapping[str, Mapping[str, Any]],
) -> RecipientChanges:
    """.sops.yaml recipient change plus per-file metadata changes."""

    files: dict[str, SetChange] = {}
    for name in sorted(set(base_files) | set(head_files)):
        change = _set_change(file_recipients(base_files.get(name, {})), file_recipients(head_files.get(name, {})))
        if change.added or change.removed:
            files[name] = change
    config_change = _set_change(config_recipients(base_config), config_recipients(head_config))
    return RecipientChanges(config=config_change, files=files)


def _sealed(encrypted: Mapping[str, Any]) -> tuple[dict[str, Any], Any]:
    meta = encrypted.get("sops", {})
    mac = meta.get("mac") if isinstance(meta, Mapping) else None
    return {key: value for key, value in encrypted.items() if key != "sops"}, mac


def _key_node(path: str) -> str | None:
    parent, _, name = path.rpartition("/")
    return name.removesuffix(".yaml") if parent == KEYS_DIR and name.endswith(".yaml") else None


def _pin_label(pin: Any) -> str:
    """Raw manifest pin label, xray release digests appended, pin failing current schema as plain string."""

    if not isinstance(pin, Mapping):
        return _artifact_pin_label(pin)
    try:
        release: VersionPin = XrayRelease.model_validate(pin)
    except ValidationError:
        return str(pin.get("version", pin))
    digests = ", ".join(f"{arch}={digest[:12]}" for arch, digest in sorted(release.sha256.items()))
    return f"{_artifact_pin_label(release)} (sha256 {digests})"


def _pins(raw: Mapping[str, Any]) -> dict[str, Any]:
    pins = {f"versions.{name}": pin for name, pin in raw.get("versions", {}).items()}
    for node_id, node in raw.get("nodes", {}).items():
        overrides = node.get("overrides", {}) if isinstance(node, Mapping) else {}
        for name, pin in overrides.get("versions", {}).items():
            pins[f"nodes.{node_id}.overrides.versions.{name}"] = pin
    return pins


def _reason(text: str, width: int = 100) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    line = next((line for line in lines if REASON_LINE.search(line)), lines[-1] if lines else "")
    return line[:width].replace("|", "\\|")


def _test_cell(result: CheckResult | None) -> str:
    if result is None:
        return "-"
    detail = _reason(result.detail)
    return f"{result.status}: {detail}" if detail else result.status


def skip_reasons(report: CheckReport) -> dict[str, list[str]]:
    """Skipped tests grouped by reason: reason -> `node kind` labels."""

    reasons: dict[str, list[str]] = {}
    for result in report.skipped:
        reasons.setdefault(result.detail or "no reason given", []).append(f"{result.node_id} {result.kind}")
    return reasons


def _change_rows(title: str, changes: list[VersionChange]) -> list[str]:
    if not changes:
        return []
    rows = [
        f"### {title}",
        "",
        "| Pin | Base | Head |",
        "|---|---|---|",
    ]
    rows += [f"| `{change.path}` | {change.before or '-'} | {change.after or '-'} |" for change in changes]
    return [*rows, ""]


def _secrets_rows(report: CheckReport) -> list[str]:
    rows: list[str] = []
    overlay = report.overlay
    if overlay.added:
        rows.append(f"- overlay paths added: {_code_list(overlay.added)}")
    if overlay.removed:
        rows.append(f"- overlay paths removed: {_code_list(overlay.removed)}")
    if overlay.changed:
        rows.append(
            f"- overlay values with new ciphertext (sops re-encrypts on every edit, so candidates only): "
            f"{_code_list(overlay.changed)}"
        )
    config = report.recipients.config
    if config.added:
        rows.append(f"- `.sops.yaml` recipients added: {_code_list(config.added)}")
    if config.removed:
        rows.append(f"- `.sops.yaml` recipients removed: {_code_list(config.removed)}")
    for name, change in report.recipients.files.items():
        added, removed = _code_list(change.added) or "-", _code_list(change.removed) or "-"
        rows.append(f"- `{name}` recipients added: {added}, removed: {removed}")
    if report.secrets_files:
        files = ", ".join(
            f"`{change.path}`" + (f" (node `{change.node}`)" if change.node else "") for change in report.secrets_files
        )
        rows.append(f"- secrets files with new ciphertext or sops mac: {files}")
    return (
        [
            "### Secrets",
            "",
            *rows,
            "",
        ]
        if rows
        else []
    )


def _detail_sections(report: CheckReport) -> list[tuple[str, str, str]]:
    sections = [
        (
            f"{result.node_id} {result.kind} output",
            "text",
            result.detail,
        )
        for result in report.failures
        if result.detail
    ]
    sections += [
        (
            f"{diff.node_id} ({diff.state})",
            "diff",
            diff.config_diff + diff.haproxy_diff or "(only masked values changed)\n",
        )
        for diff in report.nodes
        if diff.state != "unchanged"
    ]
    if report.code_diff:
        sections.append(
            (
                "runes/ and .github/",
                "diff",
                report.code_diff,
            )
        )
    return sections


def _headline(report: CheckReport) -> str:
    if report.status == "failed":
        return f"FAILED ({len(report.failures)} failing test(s))"
    if report.status == "skipped":
        return "skipped (no test ran)"
    return f"passed ({len(report.skipped)} skipped)" if report.skipped else "passed"


def render_markdown(report: CheckReport, limit: int = COMMENT_LIMIT) -> str:
    """PR comment body within `limit` chars, detail sections (failure output, then diffs) dropped when too long."""

    status = _headline(report)
    results = {(result.node_id, result.kind): result for result in report.tests}
    lines = [
        MARKER,
        "## Astrarium check",
        "",
        f"Base `{report.base}` -> head `{report.head}`: **{status}**",
        "",
    ]
    lines += [f"> warning: {warning}" for warning in report.warnings]
    if report.warnings:
        lines.append("")
    lines += ["| Node | Change | xray -test | haproxy -c |", "|---|---|---|---|"]
    lines += [
        f"| {diff.node_id} | {diff.state} | {_test_cell(results.get((diff.node_id, 'xray')))} "
        f"| {_test_cell(results.get((diff.node_id, 'haproxy')))} |"
        for diff in report.nodes
    ]
    lines.append("")
    lines += _change_rows("Version pins", report.versions)
    lines += _change_rows("Tool stack (uv.lock)", report.tool_stack)
    lines += _secrets_rows(report)
    text = "\n".join(lines) + "\n"
    reserve = len(OMISSION_NOTE) + 20
    omitted = 0
    for title, lang, body in _detail_sections(report):
        ending = body if body.endswith("\n") else body + "\n"
        block = f"\n<details><summary>{title}</summary>\n\n{FENCE}{lang}\n{ending}{FENCE}\n</details>\n"
        if len(text) + len(block) + reserve > limit:
            omitted += 1
            continue
        text += block
    if omitted:
        text += OMISSION_NOTE.format(count=omitted)
    if len(text) > limit:
        text = text[: limit - len(TRUNCATION_NOTE)] + TRUNCATION_NOTE
    return text


def summary_table(report: CheckReport) -> Table:
    """Terminal table: node, change, test status."""

    table = Table(title=f"check {report.base} -> {report.head}")
    for column in (
        "Node",
        "Change",
        "xray -test",
        "haproxy -c",
    ):
        table.add_column(column)
    results = {(result.node_id, result.kind): result for result in report.tests}
    for diff in report.nodes:
        table.add_row(
            diff.node_id,
            diff.state,
            _status(results.get((diff.node_id, "xray"))),
            _status(results.get((diff.node_id, "haproxy"))),
        )
    return table
