#!/usr/bin/env python3
"""Self-tests for scripts/verify_declared_hashes.py.

Run: python3 tests/test_verify_declared_hashes.py
No third-party dependencies; uses only the standard library.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile


SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_declared_hashes.py"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
    )


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "a.txt").write_bytes(b"alpha\n")
        (root / "b.txt").write_bytes(b"beta\n")

        manifest = root / "manifest.sha256"
        manifest.write_text(
            f"{sha256(b'alpha\n')}  a.txt\n{sha256(b'beta\n')}  b.txt\n",
            encoding="utf-8",
        )

        ok = run([str(manifest), "--root", str(root)])
        if ok.returncode != 0 or "PASS 2/2" not in ok.stdout:
            failures.append(f"positive case failed: rc={ok.returncode} {ok.stdout}{ok.stderr}")

        (root / "a.txt").write_bytes(b"alpha modified\n")
        bad = run([str(manifest), "--root", str(root)])
        if bad.returncode != 1 or "mismatch: a.txt" not in bad.stderr:
            failures.append(f"tampered-byte case failed: rc={bad.returncode} {bad.stderr}")

        (root / "a.txt").write_bytes(b"alpha\n")
        (root / "b.txt").unlink()
        missing = run([str(manifest), "--root", str(root)])
        if missing.returncode != 1 or "missing: b.txt" not in missing.stderr:
            failures.append(f"missing-file case failed: rc={missing.returncode} {missing.stderr}")

        (root / "b.txt").write_bytes(b"beta\n")
        mapping = root / "map.json"
        mapping.write_text(
            json.dumps({"a.txt": sha256(b"alpha\n"), "b.txt": sha256(b"beta\n")}),
            encoding="utf-8",
        )
        json_ok = run([str(mapping), "--format", "json", "--root", str(root)])
        if json_ok.returncode != 0 or "PASS 2/2" not in json_ok.stdout:
            failures.append(f"json map case failed: rc={json_ok.returncode} {json_ok.stdout}{json_ok.stderr}")

        listing = root / "list.json"
        listing.write_text(
            json.dumps(
                [
                    {"path": "a.txt", "sha256": sha256(b"alpha\n")},
                    {"path": "b.txt", "sha256": sha256(b"beta\n")},
                ]
            ),
            encoding="utf-8",
        )
        json_list = run([str(listing), "--format", "json", "--root", str(root)])
        if json_list.returncode != 0 or "PASS 2/2" not in json_list.stdout:
            failures.append(f"json list case failed: rc={json_list.returncode} {json_list.stdout}{json_list.stderr}")

        malformed = root / "bad.sha256"
        malformed.write_text("not-a-hash  a.txt\n", encoding="utf-8")
        bad_manifest = run([str(malformed), "--root", str(root)])
        if bad_manifest.returncode != 2:
            failures.append(f"malformed manifest should be usage error, got rc={bad_manifest.returncode}")

        empty = root / "empty.sha256"
        empty.write_text("", encoding="utf-8")
        empty_run = run([str(empty), "--root", str(root)])
        if empty_run.returncode != 2:
            failures.append(f"empty manifest should be usage error, got rc={empty_run.returncode}")

    if failures:
        for failure in failures:
            print(f"[self-test] FAIL {failure}", file=sys.stderr)
        return 1
    print(
        "[self-test] PASS manifest/json-map/json-list positive, "
        "tampered-byte and missing-file negative, malformed and empty rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
