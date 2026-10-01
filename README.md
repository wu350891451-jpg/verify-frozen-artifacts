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
```

Exit codes: `0` all matched, `1` mismatch or missing file, `2` usage or parse
error.

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
```

Covers positive manifest/JSON-map/JSON-array cases, tampered-byte and
missing-file negatives, and malformed/empty declaration rejection.

## What it does not do

A PASS means the bytes match the record. It does not mean the data is
correct, current, or trustworthy, and it does not validate business logic.

## As a Codex skill

This repository doubles as a Codex skill. Copy or install the folder so that
`SKILL.md` is discoverable; see `SKILL.md` for the workflow.

## License

MIT. See `LICENSE`.
