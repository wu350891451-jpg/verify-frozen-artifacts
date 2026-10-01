---
name: verify-frozen-artifacts
description: Verify that a manifest, audit record, or evidence file's declared SHA256 values match the actual bytes on disk. Use when checking whether frozen artifacts, delivery manifests, or audit claims have been tampered with, silently replaced, or left missing.
metadata:
  short-description: Check claimed hashes against real bytes
---

# Verify Frozen Artifacts

Check one narrow, expensive failure: a record claims a set of SHA256 values,
but the files on disk no longer hash to what the record says. That is what
happens when an artifact is edited after freezing, replaced with an older
build, or never written at all.

This tool compares **claimed bytes to observed bytes**. It says nothing about
whether the underlying data is correct, current, or trustworthy. Do not
present a PASS as evidence that data is valid.

## When to use it

- A delivery manifest, audit JSON, or evidence document lists file hashes.
- You need to confirm frozen artifacts still match their recorded values.
- A gate should fail closed when bytes changed after the freeze.

## Workflow

1. Identify the declaration source: a `sha256sum`-style manifest, a JSON file,
   or an evidence document with hashes in prose, tables, and code fences.
2. Run the matching checker.
3. Treat exit code 1 as blocking. Every mismatch, missing file, or unreadable
   record is printed with both declared and actual digests. Exit 2-4 are
   also not passes.

```bash
python3 scripts/verify_declared_hashes.py path/to/manifest.sha256 --root .
python3 scripts/verify_declared_hashes.py claims.json --format json --root . \
  --name-key path --hash-key sha256
python3 scripts/check_evidence_hashes.py sys-agents/tasks --workspace .
```

For `verify_declared_hashes.py`, exit codes are: `0` all matched, `1` mismatch
or missing file, `2` usage or parse error.

For `check_evidence_hashes.py`, exit codes are: `0` current declarations
matched, `1` mismatch or missing file, `2` parse error, `3` no current
declaration found, `4` a current declaration had no resolvable path. None of
`2`, `3`, or `4` is a pass.

## Rules that matter

- Never report success when a declaration could not be parsed. Fail closed.
- Relative paths resolve against `--root`, not the caller's cwd, so the
  check is reproducible from any directory.
- The checker does not follow symlinks for verification decisions; it reads
  whatever the resolved path points to and hashes those bytes.
- A PASS is only about byte identity. State that boundary when reporting.
- For evidence packets, only `current` declarations gate the result. Values
  marked before/old/round1/round2 are retained as history, and values
  superseded by a newer manifest are reported separately.

## Reference

`references/declaration-formats.md` shows the accepted input shapes and the
failure output format for each.
