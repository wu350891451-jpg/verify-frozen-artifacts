# verify-frozen-artifacts

Check that a manifest, audit record, or evidence file's declared SHA256
values match the actual bytes on disk.

This catches one specific failure: an artifact was edited after being frozen,
silently replaced with an older build, or never written at all, while the
recorded hash still claims otherwise.

## Usage

```bash
# sha256sum-style manifest, paths resolved against the repo root
python3 scripts/verify_declared_hashes.py manifest.sha256 --root .

# JSON object mapping path -> hash
python3 scripts/verify_declared_hashes.py claims.json --format json --root .

# JSON array with custom field names
python3 scripts/verify_declared_hashes.py claims.json --format json --root . \
  --name-key artifact --hash-key digest

# Evidence packet whose hashes are embedded in prose, code fences, or tables
python3 scripts/check_evidence_hashes.py sys-agents/tasks \
  --workspace /path/to/workspace
```

Exit codes for `verify_declared_hashes.py`: `0` all matched, `1` mismatch or
missing file, `2` usage or parse error.

Exit codes for `check_evidence_hashes.py`: `0` current declarations matched,
`1` mismatch or missing file, `2` parse error, `3` no current declaration
found, `4` a current declaration had no resolvable path. Codes `2`-`4` are
not passes.

## Example

```text
$ python3 scripts/verify_declared_hashes.py manifest.sha256 --root .
[verify] PASS 14/14 declared artifact(s) match recorded bytes

$ python3 scripts/verify_declared_hashes.py manifest.sha256 --root .
[verify] FAIL mismatch: scripts/lock.py
  declared=d8b18b76d563e142d839619155f646e2648d9ebae6a54f3cbed2b9b025ef89c2
  actual  =ce87c8c4163f9c09047083ac15ac2afc7be4267b120fe27465ad789248defc60
[verify] FAIL 1/14 declared artifact(s) did not match
```

## Testing

```bash
python3 tests/test_verify_declared_hashes.py
python3 tests/test_check_evidence_hashes.py
```

Covers positive manifest/JSON-map/JSON-array cases, tampered-byte and
missing-file negatives, and malformed/empty declaration rejection.

## Evidence packets

Evidence packets deliberately keep the pre-change baseline, the current
delivery state, and superseded freeze values in one document. The evidence
checker uses the document's task id plus the manifest chain to separate them:

- `current`: the declared value should match the file on disk;
- `historical`: the document says the value is a before/old/round value;
- `superseded`: the value was a freeze for the path, but a newer manifest
  owns that path now;
- `unresolved`: a bare digest, or a declaration without a usable path.

Only `current` declarations gate the exit code. This avoids the failure this
tool exists to catch: a stale current value that looks like an old value and
gets waved through.

## What it does not do

A PASS means the bytes match the record. It does not mean the data is
correct, current, or trustworthy, and it does not validate business logic.

## As a Codex skill

This repository doubles as a Codex skill. Copy or install the folder so that
`SKILL.md` is discoverable; see `SKILL.md` for the workflow.

## License

MIT. See `LICENSE`.
