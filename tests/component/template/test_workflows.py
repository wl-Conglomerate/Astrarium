"""Workflow hygiene, gating and CLI parity of rendered template."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import click
import pytest
import yaml

from astrarium.app import cli
from tests.support.deployment import git_commit_all
from tests.support.template import render


pytestmark = pytest.mark.component

CHECK_PATHS = [
    "astrarium.yaml",
    "topology.yaml",
    "pyproject.toml",
    "uv.lock",
    "secrets/**",
    ".sops.yaml",
    "runes/**",
    ".github/**",
]

PINNED = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

DEPLOY_GATE = "vars.ASTRARIUM_DEPLOY == 'enabled'"

CAST_GATE = "vars.ASTRARIUM_CI_CAST == 'enabled'"

DNS_GATE = "vars.ASTRARIUM_DNS_DEPLOY == 'enabled'"

FORK_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"

BUILD_COMMAND = (
    'CGO_ENABLED=0 GOOS=linux go build -o ../xray-out/xray -trimpath -buildvcs=false -gcflags="all=-l=4" '
    '-ldflags "-s -w -buildid=$SHA -X github.com/xtls/xray-core/core.build=$SHA" ./main'
)

EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

AUTO_BASE = "a1" * 20

GITHUB_SCRIPT_HARNESS = r"""
const fs = require('fs');
const [scriptPath, fixturePath] = process.argv.slice(2);
const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const outputs = {};
const warnings = [];
const core = {
  setOutput: (name, value) => { outputs[name] = value; },
  warning: (message) => { warnings.push(String(message)); },
  info: () => {},
  notice: () => {},
  setFailed: (message) => { throw new Error(String(message)); },
};
const STATUSES = ['completed', 'in_progress', 'queued', 'requested', 'waiting', 'pending'];
const matches = (run, params) => {
  if (params.branch && run.head_branch !== params.branch) return false;
  if (params.event && run.event !== params.event) return false;
  if (params.status && (STATUSES.includes(params.status) ? run.status : run.conclusion) !== params.status) return false;
  return true;
};
const perPage = (params) => Math.min(params.per_page || 30, 100);
const pageOf = (items, params) => {
  const start = ((params.page || 1) - 1) * perPage(params);
  return items.slice(start, start + perPage(params));
};
const listWorkflowRuns = async (params) => {
  const runs = fixture.runs.filter((run) => matches(run, params));
  return { data: { total_count: runs.length, workflow_runs: pageOf(runs, params) } };
};
const listJobsForWorkflowRun = async (params) => {
  const jobs = fixture.jobs[String(params.run_id)] || [];
  return { data: { total_count: jobs.length, jobs: pageOf(jobs, params) } };
};
const listed = (data) => (Array.isArray(data) ? data : Object.values(data).find(Array.isArray) || []);
async function* iterator(method, params = {}) {
  for (let page = 1; ; page += 1) {
    const chunk = listed((await method({ ...params, page })).data);
    yield { data: chunk };
    if (chunk.length < perPage(params)) return;
  }
}
const paginate = async (method, params = {}) => {
  const all = [];
  for await (const { data } of iterator(method, params)) all.push(...data);
  return all;
};
paginate.iterator = iterator;
const github = { rest: { actions: { listWorkflowRuns, listJobsForWorkflowRun } }, paginate };
const context = { repo: { owner: 'owner', repo: 'repo' }, ref: fixture.ref, runId: fixture.run_id };
const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor;
const body = new AsyncFunction('github', 'context', 'core', 'require', fs.readFileSync(scriptPath, 'utf8'));
body(github, context, core, require)
  .then(() => process.stdout.write(JSON.stringify({ outputs, warnings })))
  .catch((error) => {
    process.stderr.write(String((error && error.stack) || error));
    process.exit(1);
  });
"""

"""Runs github-script body against in-memory GitHub API honouring branch/event/status filters and paging."""


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # PyYAML reads bare `on` key as boolean True
    return workflow.get("on", workflow.get(True))


def _secrets(node: Any) -> set[str]:
    return set(re.findall(r"secrets\.([A-Z0-9_]+)", yaml.safe_dump(node)))


def _step_env(step: dict[str, Any], values: dict[str, str]) -> dict[str, str]:
    return {
        key: next((value for path, value in values.items() if path in str(expression)), "")
        for key, expression in step.get("env", {}).items()
    }


@pytest.fixture(scope="module")
def workflows(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    out = render(tmp_path_factory.mktemp("template"), has_dns=True)
    return {
        path.name: yaml.safe_load(path.read_text()) for path in sorted((out / ".github" / "workflows").glob("*.yaml"))
    }


def _steps(workflow: dict[str, Any]) -> Iterator[tuple[str, dict[str, Any], dict[str, Any]]]:
    for job_id, job in workflow["jobs"].items():
        for step in job.get("steps", []):
            yield (
                job_id,
                job,
                step,
            )


def _command(words: list[str]) -> click.Command:
    command: click.Command = cli
    for word in words:
        if not isinstance(command, click.Group) or word not in command.commands:
            break
        command = command.commands[word]
    return command


def _run_with_stub_uv(
    tmp_path: Path,
    script: str,
    cwd: Path,
    env: dict[str, str],
) -> tuple[subprocess.CompletedProcess[str], list[str] | None]:
    """Run step script under bash with `uv` recording its argv, argv None when uv never ran."""

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    stub = bin_dir / "uv"
    stub.write_text('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$UV_ARGS_FILE"\n')
    stub.chmod(0o755)
    args_file = tmp_path / "uv-args"
    run_env = {
        **os.environ,
        **env,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_SHA": "f" * 40,
        "UV_ARGS_FILE": str(args_file),
    }
    result = subprocess.run(
        [
            "bash",
            "-c",
            script,
        ],
        cwd=cwd,
        env=run_env,
        capture_output=True,
        text=True,
    )
    return result, args_file.read_text().splitlines() if args_file.exists() else None


"""Runs github-script body against in-memory GitHub API honouring branch/event/status filters and paging."""


class _RunHistory:
    """Runs of deploy.yaml newest first, with jobs per run, as GitHub API lists them."""

    def __init__(self, apply_job: str, apply_steps: list[str], marker: str) -> None:
        self.apply_job = apply_job
        self.apply_steps = apply_steps
        self.marker = marker
        self.runs: list[dict[str, Any]] = []
        self.jobs: dict[str, list[dict[str, Any]]] = {}

    def add(
        self,
        *,
        branch: str,
        head: str,
        marker: str | None,
        event: str = "push",
        status: str = "completed",
        conclusion: str = "success",
    ) -> None:
        """Append older run, `marker` = marker step conclusion (None: apply job skipped or unfinished)."""

        run_id = 100_000 - len(self.runs)
        done = status == "completed"
        self.runs.append(
            {
                "id": run_id,
                "head_sha": head,
                "head_branch": branch,
                "event": event,
                "status": status,
                "conclusion": conclusion if done else None,
            }
        )
        steps = [
            {"name": name, "conclusion": marker if name == self.marker else "success"} for name in self.apply_steps
        ]
        self.jobs[str(run_id)] = [
            {
                "name": self.apply_job,
                "status": status,
                "conclusion": (conclusion if marker is not None else "skipped") if done else None,
                "steps": steps if marker is not None else [],
            }
        ]


def _run_github_script(workdir: Path, script: str, history: _RunHistory, env: dict[str, str]) -> dict[str, Any]:
    """Outputs and warnings of github-script body run by node against `history`."""

    workdir.mkdir()
    (workdir / "harness.cjs").write_text(GITHUB_SCRIPT_HARNESS)
    (workdir / "script.js").write_text(script)
    fixture = {
        "ref": "refs/heads/main",
        "run_id": history.runs[0]["id"],
        "runs": history.runs,
        "jobs": history.jobs,
    }
    (workdir / "fixture.json").write_text(json.dumps(fixture))
    result = subprocess.run(
        [
            "node",
            "harness.cjs",
            "script.js",
            "fixture.json",
        ],
        cwd=workdir,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_dns_workflows_only_with_dns(tmp_path: Path) -> None:
    names = {path.name for path in (render(tmp_path) / ".github" / "workflows").glob("*.yaml")}

    assert names == {"check.yaml", "deploy.yaml"}


def test_actions_pinned_by_sha_and_checkouts_drop_credentials(workflows: dict[str, dict[str, Any]]) -> None:
    for name, workflow in workflows.items():
        for job_id, _, step in _steps(workflow):
            if "uses" not in step:
                continue
            assert PINNED.match(step["uses"]), f"{name}:{job_id}: {step['uses']}"
            if step["uses"].startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") is False, f"{name}:{job_id}"


def test_permissions_explicit_and_write_tokens_never_run_repo_code(workflows: dict[str, dict[str, Any]]) -> None:
    for name, workflow in workflows.items():
        assert "permissions" in workflow, name
        for job_id, job in workflow["jobs"].items():
            assert "permissions" in job, f"{name}:{job_id}"
            if "write" in job["permissions"].values():
                steps = job.get("steps", [])
                assert not any("run" in step for step in steps), f"{name}:{job_id}"
                assert not any(step.get("uses", "").startswith("actions/checkout@") for step in steps), (
                    f"{name}:{job_id}"
                )


def test_run_scripts_take_inputs_through_env_only(workflows: dict[str, dict[str, Any]]) -> None:
    for name, workflow in workflows.items():
        for job_id, _, step in _steps(workflow):
            assert "${{" not in step.get("run", ""), f"{name}:{job_id}:{step.get('name')}"


def test_check_runs_on_pull_request_for_deployment_paths(workflows: dict[str, dict[str, Any]]) -> None:
    triggers = _triggers(workflows["check.yaml"])

    assert set(triggers) == {"pull_request"}
    assert triggers["pull_request"]["paths"] == CHECK_PATHS
    assert all("pull_request_target" not in _triggers(workflow) for workflow in workflows.values())


def test_deploy_is_gated_scoped_and_keeps_secrets_in_environment(workflows: dict[str, dict[str, Any]]) -> None:
    deploy = workflows["deploy.yaml"]
    push = _triggers(deploy)["push"]
    jobs = deploy["jobs"]
    in_env = {job_id for job_id, job in jobs.items() if job.get("environment") == "production"}

    assert push["branches"] == ["main"]
    assert push["paths"] == [path for path in CHECK_PATHS if path != ".github/**"]
    assert all(DEPLOY_GATE in job["if"] for job in jobs.values())
    assert in_env == {
        "deploy",
        "versions-apply",
        "provision",
    }
    assert all(CAST_GATE in jobs[job_id]["if"] for job_id in ("versions-apply", "provision"))
    for job_id, job in jobs.items():
        if job_id not in in_env:
            assert _secrets(job) <= {"PHOTON_READ_TOKEN"}, job_id
    for workflow in workflows.values():
        for job in workflow["jobs"].values():
            if "SOPS_AGE_KEY" in _secrets(job):
                assert job.get("environment") == "production"


def test_dns_changes_trigger_dns_workflows_only(workflows: dict[str, dict[str, Any]]) -> None:
    assert _triggers(workflows["dns-deploy.yaml"])["push"]["paths"] == ["dns/**"]
    assert _triggers(workflows["dns-validate.yaml"])["pull_request"]["paths"] == ["dns/**"]
    assert not any(path.startswith("dns") for path in _triggers(workflows["deploy.yaml"])["push"]["paths"])
    assert all(DNS_GATE in job["if"] for job in workflows["dns-deploy.yaml"]["jobs"].values())


def test_xray_builds_use_documented_flags_at_the_pinned_commit(workflows: dict[str, dict[str, Any]]) -> None:
    for name in ("check.yaml", "deploy.yaml"):
        steps = workflows[name]["jobs"]["build-xray"]["steps"]
        build = next(step for step in steps if "go build" in step.get("run", ""))
        checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))

        assert BUILD_COMMAND in build["run"], name
        assert 'test "$(git rev-parse HEAD)" = "$SHA"' in build["run"], name
        assert checkout["with"]["repository"] == "XTLS/Xray-core", name
        assert checkout["with"]["ref"] == "${{ matrix.sha }}", name


def test_workflow_arium_flags_exist_on_cli(workflows: dict[str, dict[str, Any]]) -> None:
    checked = 0
    for workflow in workflows.values():
        for _, _, step in _steps(workflow):
            script = step.get("run", "")
            match = re.search(r"uv run arium ((?:[a-z][a-z-]* )+)", script + " ")
            if match is None:
                continue
            command = _command(match.group(1).split())
            known = {opt for param in command.params for opt in [*param.opts, *param.secondary_opts]}
            used = set(re.findall(r"(?<![\w-])--[a-z][a-z0-9-]*", script))
            assert used <= known, f"{command.name}: {sorted(used - known)}"
            checked += 1

    assert checked >= 5


def test_cast_jobs_load_deploy_and_cast_keys_into_one_agent(workflows: dict[str, dict[str, Any]]) -> None:
    """Provision and versions-apply authenticate through ssh-agent, never static identity file."""

    deploy = workflows["deploy.yaml"]
    for job_id in ("versions-apply", "provision"):
        job = deploy["jobs"][job_id]
        assert {"ASTRARIUM_DEPLOY_SSH_KEY", "ASTRARIUM_CAST_SSH_KEY"} <= _secrets(job), job_id
        steps = job["steps"]
        assert any("ssh-agent -s" in step.get("run", "") for step in steps), job_id
        assert any("SSH_AUTH_SOCK" in step.get("run", "") and "GITHUB_ENV" in step.get("run", "") for step in steps), (
            job_id
        )
        kill = next(step for step in steps if "ssh-agent -k" in step.get("run", ""))
        assert "always()" in kill.get("if", ""), job_id


def test_pr_comment_jobs_run_only_for_same_repo_pulls(workflows: dict[str, dict[str, Any]]) -> None:
    """Fork PR comment job never gets pull-requests: write token."""

    assert FORK_GUARD in workflows["check.yaml"]["jobs"]["comment"]["if"]
    assert FORK_GUARD in workflows["dns-validate.yaml"]["jobs"]["comment"]["if"]


def test_deploy_key_file_written_under_a_restrictive_umask(workflows: dict[str, dict[str, Any]]) -> None:
    """umask 077 precedes key file write."""

    steps = workflows["deploy.yaml"]["jobs"]["deploy"]["steps"]
    install_key = next(step for step in steps if "id_ed25519" in step.get("run", ""))

    assert re.search(
        r"umask 077.*id_ed25519",
        install_key["run"],
        re.DOTALL,
    )


def test_versions_apply_gates_on_deploy_and_supports_manual_catch_up(workflows: dict[str, dict[str, Any]]) -> None:
    """Automatic runs need successful deploy, manual catch-up runs without one, skipped needs never cancel it."""

    deploy = workflows["deploy.yaml"]
    action_input = _triggers(deploy)["workflow_dispatch"]["inputs"]["action"]
    since_input = _triggers(deploy)["workflow_dispatch"]["inputs"]["since"]
    versions_apply = deploy["jobs"]["versions-apply"]

    assert "versions-apply" in action_input["options"]
    assert since_input["default"] == ""
    assert "!cancelled()" in versions_apply["if"]
    assert "needs.deploy.result == 'success'" in versions_apply["if"]
    assert "needs.deploy.result == 'skipped'" in versions_apply["if"]
    assert "inputs.action == 'versions-apply'" in versions_apply["if"]
    assert versions_apply["permissions"]["actions"] == "read"
    base_step = next(step for step in versions_apply["steps"] if step.get("id") == "base")
    assert base_step["uses"].startswith("actions/github-script@")


@pytest.mark.parametrize(
    ("since", "expected"),
    [(" \t ", AUTO_BASE), (" 0123abcd ", "0123abcd")],
    ids=["blank-means-auto-base", "padded-ref-trimmed"],
)
def test_versions_apply_changed_since_takes_since_input_else_auto_base(
    tmp_path: Path,
    workflows: dict[str, dict[str, Any]],
    since: str,
    expected: str,
) -> None:
    """Trimmed `since` input wins, blank falls back to base step output."""

    steps = workflows["deploy.yaml"]["jobs"]["versions-apply"]["steps"]
    apply = next(step for step in steps if "arium versions apply" in step.get("run", ""))
    env = _step_env(apply, {"inputs.since": since, "steps.base.outputs.ref": AUTO_BASE})

    result, args = _run_with_stub_uv(
        tmp_path,
        apply["run"],
        tmp_path,
        env,
    )

    assert result.returncode == 0, result.stderr
    assert args is not None
    assert args[args.index("--changed-since") + 1] == expected


def test_versions_apply_base_is_head_of_last_run_that_recorded_apply(
    tmp_path: Path, workflows: dict[str, dict[str, Any]]
) -> None:
    """Base = head of newest run on branch (push or dispatch) whose apply job passed non-dry-run marker step.

    Scans past first page of runs, skips dry runs, failed applies and other branches, warns on event.before fallback.
    """

    job = workflows["deploy.yaml"]["jobs"]["versions-apply"]
    steps = job["steps"]
    apply_index = next(i for i, step in enumerate(steps) if "arium versions apply" in step.get("run", ""))
    marker_index, marker = next((i, step) for i, step in enumerate(steps) if "inputs.dry_run" in step.get("if", ""))
    assert marker_index > apply_index
    assert not re.search(r"\b(always|failure|cancelled)\(\)", marker["if"])
    assert "inputs.limit" in marker["if"], "limited dispatch must not record applied base"
    if shutil.which("node") is None:
        pytest.skip("needs node to run github-script body")

    base_step = next(step for step in steps if step.get("id") == "base")
    before = "7" * 40
    env = _step_env(base_step, {"github.event.before": before})
    history = _RunHistory(
        job["name"],
        [step.get("name", step.get("uses", "run")) for step in steps],
        marker["name"],
    )
    history.add(
        branch="main",
        head="c" * 40,
        marker=None,
        status="in_progress",
    )
    history.add(
        branch="feature",
        head="e" * 40,
        marker="success",
        event="workflow_dispatch",
    )
    history.add(
        branch="main",
        head="d" * 40,
        marker="skipped",
        event="workflow_dispatch",
    )
    history.add(
        branch="main",
        head="8" * 40,
        marker="skipped",
        conclusion="failure",
    )
    for index in range(120):
        history.add(
            branch="main",
            head=f"{index:040x}",
            marker=None,
            event=("push", "workflow_dispatch")[index % 2],
        )

    fallback = _run_github_script(
        tmp_path / "fallback",
        base_step["with"]["script"],
        history,
        env,
    )
    # older runs: catch-up dispatch that applied, then push that applied before it
    history.add(
        branch="main",
        head="b" * 40,
        marker="success",
        event="workflow_dispatch",
    )
    history.add(
        branch="main",
        head="a" * 40,
        marker="success",
    )
    anchored = _run_github_script(
        tmp_path / "anchored",
        base_step["with"]["script"],
        history,
        env,
    )

    assert anchored["outputs"]["ref"] == "b" * 40
    assert not anchored["warnings"]
    assert fallback["outputs"]["ref"] == before
    assert fallback["warnings"]


def test_manticora_steps_get_cloudflare_token_kept_in_production_environment(
    workflows: dict[str, dict[str, Any]],
) -> None:
    """Every manticora step sees CLOUDFLARE_API_TOKEN, write token secret only reaches production jobs."""

    production_steps = 0
    for name, workflow in workflows.items():
        for job_id, job in workflow["jobs"].items():
            production = job.get("environment") == "production"
            if "CLOUDFLARE_API_TOKEN" in _secrets(job):
                assert production, f"{name}:{job_id}"
            for step in job.get("steps", []):
                if "uv run manticora" not in step.get("run", ""):
                    continue
                assert "CLOUDFLARE_API_TOKEN" in step.get("env", {}), f"{name}:{job_id}:{step.get('name')}"
                if production:
                    assert "CLOUDFLARE_API_TOKEN" in _secrets(step), f"{name}:{job_id}:{step.get('name')}"
                    production_steps += 1

    assert production_steps


@pytest.mark.parametrize(
    (
        "event",
        "base_ref",
        "expected",
    ),
    [
        (
            "workflow_dispatch",
            " \t ",
            None,
        ),
        (
            "workflow_dispatch",
            "no-such-ref",
            None,
        ),
        (
            "workflow_dispatch",
            " HEAD ",
            "HEAD",
        ),
        (
            "push",
            "0" * 40,
            EMPTY_TREE,
        ),
    ],
    ids=[
        "dispatch-blank-fails",
        "dispatch-unresolvable-fails",
        "dispatch-padded-ref-trimmed",
        "push-all-zero-empty-tree",
    ],
)
def test_dns_deploy_base_ref(
    tmp_path: Path,
    workflows: dict[str, dict[str, Any]],
    event: str,
    base_ref: str,
    expected: str | None,
) -> None:
    """Manual dispatch needs resolvable base_ref, push without old tip deploys from empty tree."""

    step = next(
        step
        for step in workflows["dns-deploy.yaml"]["jobs"]["deploy"]["steps"]
        if "uv run manticora" in step.get("run", "")
    )
    repo = tmp_path / "repo"
    (repo / step.get("working-directory", ".")).mkdir(parents=True)
    git_commit_all(repo)
    env = {**_step_env(step, {"inputs.base_ref": base_ref, "github.event_name": event}), "GITHUB_EVENT_NAME": event}

    result, args = _run_with_stub_uv(
        tmp_path,
        step["run"],
        repo / step.get("working-directory", "."),
        env,
    )

    if expected is None:
        assert result.returncode != 0
        assert args is None
    else:
        assert result.returncode == 0, result.stderr
        assert args is not None
        assert args[args.index("--base-ref") + 1] == expected


def test_dispatchable_jobs_read_limit_and_dry_run_when_supported(workflows: dict[str, dict[str, Any]]) -> None:
    """Dispatchable job never drops --limit/--dry-run when its arium command accepts them."""

    deploy = workflows["deploy.yaml"]
    checked = 0
    for job_id, job in deploy["jobs"].items():
        for step in job.get("steps", []):
            script = step.get("run", "")
            match = re.search(r"uv run arium ((?:[a-z][a-z-]* )+)", script + " ")
            if match is None:
                continue
            command = _command(match.group(1).split())
            known = {opt for param in command.params for opt in [*param.opts, *param.secondary_opts]}
            env = step.get("env", {})
            if "--limit" in known:
                assert "${{ inputs.limit }}" in env.values(), f"{job_id}: inputs.limit not read"
                assert "--limit" in script, f"{job_id}: --limit never reaches {command.name}"
                checked += 1
            if "--dry-run" in known:
                assert "${{ inputs.dry_run }}" in env.values(), f"{job_id}: inputs.dry_run not read"
                assert "--dry-run" in script, f"{job_id}: --dry-run never reaches {command.name}"
                checked += 1

    assert checked >= 4
