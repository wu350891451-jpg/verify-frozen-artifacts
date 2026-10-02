# Verify Frozen Artifacts

[![CI](https://github.com/wu350891451-jpg/verify-frozen-artifacts/actions/workflows/ci.yml/badge.svg)](https://github.com/wu350891451-jpg/verify-frozen-artifacts/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Fail CI when a manifest or an AI-agent evidence packet claims a SHA256 that
no longer matches the bytes on disk.

Usage guide and search entry point: https://wu350891451-jpg.github.io/verify-frozen-artifacts/

This catches a specific and expensive failure: an artifact was edited after
being frozen, silently replaced with an older build, or never written at all,
while the record still claims the original bytes.

It is not another checksum utility. Two things are different:

1. Evidence packets mix current, historical, and superseded hashes in the
   same Markdown file. This tool separates them instead of treating every
   digest as a current claim.
2. It fails closed. A mismatch, missing file, parse error, or unresolvable
   declaration is never reported as a pass.

## 30-second demo

```bash
git clone https://github.com/wu350891451-jpg/verify-frozen-artifacts.git
cd verify-frozen-artifacts

python3 scripts/verify_declared_hashes.py demo/manifest.sha256 --root demo
# [verify] PASS 1/1 declared artifact(s) match recorded bytes
```

Now change the protected artifact:

```bash
printf 'tampered\n' >> demo/artifact.txt
python3 scripts/verify_declared_hashes.py demo/manifest.sha256 --root demo
# [verify] FAIL mismatch: artifact.txt
#   declared=b4862708...
#   actual  =...
# exit code 1
```

Restore the demo with `git restore demo/artifact.txt`.

No dependencies. Python 3.8 or newer.

## Use in GitHub Actions

Standard manifest:

```yaml
name: Verify frozen artifacts

on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wu350891451-jpg/verify-frozen-artifacts@v0.2.0
        with:
          declaration: artifacts.sha256
          root: .
```

AI-agent evidence packet:

```yaml
      - uses: wu350891451-jpg/verify-frozen-artifacts@v0.2.0
        with:
          evidence-path: sys-agents/tasks
          workspace: .
```

Set either `declaration` or `evidence-path`, not both. For security-sensitive
repositories, pin the action to a commit SHA rather than a tag.

## Command line

```bash
# sha256sum-style manifest
python3 scripts/verify_declared_hashes.py manifest.sha256 --root .

# JSON object mapping path to digest
python3 scripts/verify_declared_hashes.py claims.json --format json --root .

# JSON array with custom field names
python3 scripts/verify_declared_hashes.py claims.json --format json --root . \
  --name-key artifact --hash-key digest

# Evidence packet with hashes in prose, code fences, or tables
python3 scripts/check_evidence_hashes.py sys-agents/tasks --workspace .
```

The manifest checker exits `0` when every declaration matches, `1` on a
mismatch or missing file, and `2` on a usage or parse error.

The evidence checker exits:

| Code | Meaning |
|---:|---|
| `0` | Every current declaration matched |
| `1` | Mismatch, missing file, or ambiguous path |
| `2` | Parse error |
| `3` | No document contained a current declaration |
| `4` | A current declaration had no resolvable path |

Codes `2`, `3`, and `4` are not passes.

## Evidence packet semantics

Evidence documents often keep the pre-change baseline and the delivery state
in one file. The checker uses the task id and manifest chain to classify each
declaration:

- `current`: the digest should match the file on disk;
- `historical`: the document marks it as before, old, or a round value;
- `superseded`: a newer manifest now owns that path;
- `stale`: the document still presents an older freeze as current, so it fails;
- `unresolved`: a bare digest or a declaration without a usable path.

Only current declarations gate the exit code. This avoids waving through a
stale value merely because it looks historical.

## What it does not do

A pass means the declared bytes are the bytes on disk. It does not prove that
the data is correct, current, authentic, or trustworthy, and it does not
validate business logic.

This is not a signing or provenance system. Use Sigstore, cosign, in-toto, or
SLSA when the threat model includes a malicious publisher rather than an
accidental post-freeze edit or a stale evidence claim.

## As a Codex skill

The repository also contains `SKILL.md`. Install the folder in a skill
directory when you want an agent to run the same fail-closed check and report
current, historical, and superseded declarations correctly.

## Development

```bash
python3 tests/test_verify_declared_hashes.py
python3 tests/test_check_evidence_hashes.py
```

CI runs the tests on Python 3.8 and 3.12, runs the tamper demo, and exercises
the composite action.

## License

MIT. See `LICENSE`.
