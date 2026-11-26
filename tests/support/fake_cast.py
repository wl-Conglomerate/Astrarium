"""Stand-ins for `python -m nullforge.cli cast`: pyinfra --json documents and fake interpreter."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


def documents(*docs: dict[str, Any]) -> str:
    return "".join(json.dumps(doc) + "\n" for doc in docs)


def recorded_calls(record: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in record.read_text(encoding="utf-8").splitlines()]


def results_doc(ops: Mapping[str, Sequence[str]] | None = None, failed: Sequence[str] = ()) -> dict[str, Any]:
    """Document of pyinfra_cli.prints.print_run_json(state, dry=False), ops maps op name -> hosts."""

    changes = {} if ops is None else dict(ops)
    operations = [
        {
            "op_hash": f"h{index}",
            "name": f"{name} (secret-arg)",
            "names": [name],
            "args": ["secret-arg"],
            "hosts": len(hosts),
            "success": sorted(hosts),
            "error": [],
            "no_change": [],
        }
        for index, (name, hosts) in enumerate(changes.items())
    ]
    totals = {
        "hosts": 0,
        "success": 0,
        "error": 0,
        "no_change": 0,
    }
    return {
        "plan": [],
        "results": {
            "operations": operations,
            "totals": totals,
            "failed_hosts": sorted(failed),
        },
    }


def dry_doc(
    ops: Mapping[str, Sequence[str]] | None = None, conditional: Mapping[str, Sequence[str]] | None = None
) -> dict[str, Any]:
    """Document of `print_run_json(state, dry=True)` (pyinfra_cli/prints.py:103-130,183-189)."""

    changes = {} if ops is None else dict(ops)
    maybe = {} if conditional is None else dict(conditional)
    plan = [
        {
            "op_hash": f"p{index}",
            "name": f"{name} (secret-arg)",
            "names": [name],
            "args": ["secret-arg"],
            "hosts_with_change": sorted(changes.get(name, [])),
            "hosts_with_conditional_change": sorted(maybe.get(name, [])),
        }
        for index, name in enumerate(dict.fromkeys([*changes, *maybe]))
    ]
    return {"plan": plan, "results": None}


def fake_python(tmp_path: Path, *, stdout: str, rc: int = 0, stderr_lines: Sequence[str] = ()) -> tuple[Path, Path]:
    """Executable standing in for interpreter: records argv, cwd and env, prints stdout, exits rc."""

    record = tmp_path / "fake-cast-calls.jsonl"
    script = tmp_path / "fake-python"
    script.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        f"with open({str(record)!r}, 'a', encoding='utf-8') as handle:\n"
        "    handle.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), 'env': dict(os.environ)}) + '\\n')\n"
        f"for line in {list(stderr_lines)!r}:\n"
        "    print(line, file=sys.stderr)\n"
        f"sys.stdout.write({stdout!r})\n"
        f"sys.exit({rc})\n",
        encoding="utf-8",
    )
    script.chmod(0o755)
    return script, record
