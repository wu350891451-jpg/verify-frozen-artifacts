#!/usr/bin/env python3
"""Self-tests for scripts/check_evidence_hashes.py."""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


REPO = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_evidence_hashes.py"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def write_fixture(
    root: pathlib.Path,
    name: str,
    text: str,
    manifest_lines: list[tuple[str, str]] | None = None,
) -> pathlib.Path:
    tasks = root / "sys-agents" / "tasks"
    manifests = root / "sys-agents" / "manifests"
    tasks.mkdir(parents=True, exist_ok=True)
    manifests.mkdir(parents=True, exist_ok=True)
    document = tasks / name
    document.write_text(text, encoding="utf-8")
    if manifest_lines:
        (manifests / "TASK-20990101-001.sha256").write_text(
            "".join(f"{digest}  {path}\n" for digest, path in manifest_lines),
            encoding="utf-8",
        )
    return document


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        alpha = root / "alpha.py"
        beta = root / "beta.py"
        alpha.write_bytes(b"alpha\n")
        beta.write_bytes(b"beta\n")
        alpha_hash = sha256(b"alpha\n")
        beta_hash = sha256(b"beta\n")

        document = write_fixture(
            root,
            "TASK-20990101-001-evidence.md",
            f"""---
task_id: TASK-20990101-001
---
# Evidence

## Current

```text
{alpha_hash}  alpha.py
```

## Before and after

### After

```text
{alpha_hash}  alpha.py
```

### Before

```text
{beta_hash}  alpha.py
```

```text
round1: {beta_hash}
round2: {beta_hash}
```
""",
            [(alpha_hash, "alpha.py")],
        )
        ok = run([str(document), "--workspace", str(root)])
        if ok.returncode != 0 or "PASS 2/2" not in ok.stdout:
            failures.append(f"positive case failed: rc={ok.returncode} {ok.stdout}{ok.stderr}")

        alpha.write_bytes(b"changed\n")
        bad = run([str(document), "--workspace", str(root)])
        if bad.returncode != 1 or "mismatch" not in bad.stdout:
            failures.append(f"tamper case failed: rc={bad.returncode} {bad.stdout}{bad.stderr}")

        alpha.write_bytes(b"alpha\n")
        table = write_fixture(
            root,
            "TASK-20990101-002-evidence.md",
            f"""---
task_id: TASK-20990101-002
---
| 文件 | 改前 SHA256 | 改后 SHA256 |
|---|---|---|
| `alpha.py` | `{beta_hash}` | `{alpha_hash}` |
""",
            [(alpha_hash, "alpha.py")],
        )
        table_run = run([str(table), "--workspace", str(root)])
        if table_run.returncode not in (0, 4):
            failures.append(
                f"table case failed: rc={table_run.returncode} "
                f"{table_run.stdout}{table_run.stderr}"
            )

        missing = write_fixture(
            root,
            "TASK-20990101-003-evidence.md",
            f"""---
task_id: TASK-20990101-003
---
```text
{alpha_hash}  sys-scripts/not-there.py
```
""",
        )
        missing_run = run([str(missing), "--workspace", str(root)])
        if missing_run.returncode != 1 or "missing" not in missing_run.stdout:
            failures.append(
                f"missing case failed: rc={missing_run.returncode} "
                f"{missing_run.stdout}{missing_run.stderr}"
            )

        stale = write_fixture(
            root,
            "TASK-20990101-001-evidence.md",
            f"""---
task_id: TASK-20990101-001
---
```text
{beta_hash}  alpha.py
```
""",
            [(alpha_hash, "alpha.py"), (beta_hash, "alpha.py")],
        )
        stale_run = run([str(stale), "--workspace", str(root)])
        if stale_run.returncode != 1:
            failures.append(
                f"stale-current case should fail, rc={stale_run.returncode} "
                f"{stale_run.stdout}{stale_run.stderr}"
            )

        no_claims = write_fixture(
            root,
            "TASK-20990101-004-evidence.md",
            "# no hashes here\n",
        )
        no_claims_run = run([str(no_claims), "--workspace", str(root)])
        if no_claims_run.returncode != 3:
            failures.append(
                f"no-current-claims should exit 3, rc={no_claims_run.returncode}"
            )

        json_run = run([str(document), "--workspace", str(root), "--json"])
        try:
            json.loads(json_run.stdout)
        except json.JSONDecodeError:
            failures.append("--json output was not valid JSON")

    if failures:
        for failure in failures:
            print(f"[self-test] FAIL {failure}", file=sys.stderr)
        return 1
    print(
        "[self-test] PASS current, before/after, table, missing, stale, "
        "no-claim, and JSON paths"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
