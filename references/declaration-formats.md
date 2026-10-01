# Declaration Formats

The checker accepts two families of declaration. Both feed the same
comparison: declared digest versus actual digest of the file on disk.

## 1. Manifest format

Standard `sha256sum` output. One record per line:

```text
d8b18b76d563e142d839619155f646e2648d9ebae6a54f3cbed2b9b025ef89c2  scripts/lock.py
39a3e7e2f2d9513b072d9e0356b6b7d2d68bcd0b9d26dc4108362bb8beddfff6b  scripts/hash.py
```

Accepted details:

- Exactly two whitespace-separated fields: digest, then path.
- A leading `*` on the path (binary-mode marker) is stripped.
- Blank lines and lines starting with `#` are ignored.
- The digest must be 64 lowercase or uppercase hex characters.

Rejections, which exit 2 rather than 0:

- A line without two fields.
- A digest that is not 64 hex characters.
- An empty path.
- A file that contains no records.

## 2. JSON map format

An object mapping path to digest:

```json
{
  "scripts/lock.py": "d8b18b76d563e142d839619155f646e2648d9ebae6a54f3cbed2b9b025ef89c2",
  "scripts/hash.py": "39a3e7e2f2d9513b072d9e0356b6b7d2d68bcd0b9d26dc4108362bb8beddfff6b"
}
```

Run with `--format json`.

## 3. JSON array format

An array of objects, using configurable key names:

```json
[
  {"path": "scripts/lock.py", "sha256": "d8b18b76d563e142d839619155f646e2648d9ebae6a54f3cbed2b9b025ef89c2"},
  {"path": "scripts/hash.py", "sha256": "39a3e7e2f2d9513b072d9e0356b6b7d2d68bcd0b9d26dc4108362bb8beddfff6b"}
]
```

Run with:

```bash
python3 scripts/verify_declared_hashes.py claims.json --format json \
  --name-key path --hash-key sha256
```

Change `--name-key` and `--hash-key` when a downstream schema uses different
field names, such as `artifact` and `digest`.

## Output

Success:

```text
[verify] PASS 14/14 declared artifact(s) match recorded bytes
```

Mismatch:

```text
[verify] FAIL mismatch: scripts/lock.py
  declared=d8b18b76d563e142d839619155f646e2648d9ebae6a54f3cbed2b9b025ef89c2
  actual  =ce87c8c4163f9c09047083ac15ac2afc7be4267b120fe27465ad789248defc60
[verify] FAIL 1/14 declared artifact(s) did not match
```

Missing file:

```text
[verify] FAIL missing: scripts/removed.py
```

Usage or parse error:

```text
[verify] ERROR cannot parse claims.json: line 3: invalid SHA256 'not-a-hash'
```

Exit codes are stable and safe to gate on: `0` all matched, `1` mismatch or
missing, `2` usage or parse error. Do not treat exit 2 as a pass.
