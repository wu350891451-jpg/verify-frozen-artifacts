# 30-second demo

This directory contains a real manifest and the artifact it protects.

```bash
python3 scripts/verify_declared_hashes.py demo/manifest.sha256 --root demo
```

Expected result:

```text
[verify] PASS 1/1 declared artifact(s) match recorded bytes
```

Now change one byte in `demo/artifact.txt` and run the command again. The
checker prints the declared and actual digests and exits with code `1`.
