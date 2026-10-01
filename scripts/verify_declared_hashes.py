#!/usr/bin/env python3
"""Verify that every declared SHA256 matches the actual bytes on disk.

The failure this tool catches is narrow and expensive: a manifest, audit
record, or evidence document claims a set of SHA256 values, but one of the
files on disk no longer hashes to the value it is recorded against. That
happens when an artifact is edited after freezing, silently replaced with an
older build, or never written to disk at all.

This checker only compares claimed bytes to observed bytes. It says nothing
about whether the data itself is correct, current, or trustworthy.

Exit codes:
    0 = every declared hash matched
    1 = mismatch, missing file, or unreadable input
    2 = usage or configuration error
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_manifest(text: str) -> list[tuple[str, str]]:
    """Parse ``<sha256>  <path>`` lines, the sha256sum output format."""
    records: list[tuple[str, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise ValueError(f"line {lineno}: expected '<sha256>  <path>'")
        digest, raw_path = parts[0].lower(), parts[1].strip().lstrip("*")
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"line {lineno}: invalid SHA256 {digest!r}")
        if not raw_path:
            raise ValueError(f"line {lineno}: empty path")
        records.append((digest, raw_path))
    return records


def parse_json_map(text: str, name_key: str, hash_key: str) -> list[tuple[str, str]]:
    """Parse a JSON array of objects, or an object mapping path -> hash."""
    payload = json.loads(text)
    records: list[tuple[str, str]] = []
    if isinstance(payload, dict):
        for raw_path, digest in payload.items():
            records.append((str(digest).lower(), str(raw_path)))
        return records
    if isinstance(payload, list):
        for index, item in enumerate(payload):
            if not isinstance(item, dict):
                raise ValueError(f"item {index}: expected an object")
            try:
                raw_path = str(item[name_key])
                digest = str(item[hash_key]).lower()
            except KeyError as exc:
                raise ValueError(
                    f"item {index}: missing key {exc.args[0]!r}"
                ) from exc
            records.append((digest, raw_path))
        return records
    raise ValueError("expected a JSON object or array")


def load_declarations(path: pathlib.Path, fmt: str, name_key: str, hash_key: str):
    text = path.read_text(encoding="utf-8")
    if fmt == "manifest":
        return parse_manifest(text)
    return parse_json_map(text, name_key, hash_key)


def verify(
    records: list[tuple[str, str]],
    root: pathlib.Path,
) -> tuple[list[str], int]:
    failures: list[str] = []
    for digest, raw_path in records:
        if len(digest) != 64:
            failures.append(f"invalid declared SHA256 for {raw_path}: {digest!r}")
            continue
        path = pathlib.Path(raw_path)
        if not path.is_absolute():
            path = root / path
        if not path.is_file():
            failures.append(f"missing: {raw_path}")
            continue
        actual = sha256_file(path)
        if actual != digest:
            failures.append(
                f"mismatch: {raw_path}\n"
                f"  declared={digest}\n"
                f"  actual  ={actual}"
            )
    return failures, len(records)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="verify declared SHA256 values against bytes on disk"
    )
    parser.add_argument("declaration", help="manifest or JSON file holding the claims")
    parser.add_argument(
        "--root",
        default=".",
        help="directory used to resolve relative paths (default: cwd)",
    )
    parser.add_argument(
        "--format",
        choices=["manifest", "json"],
        default="manifest",
        help="declaration format (default: manifest, i.e. sha256sum output)",
    )
    parser.add_argument(
        "--name-key",
        default="path",
        help="JSON object key holding the file path (default: path)",
    )
    parser.add_argument(
        "--hash-key",
        default="sha256",
        help="JSON object key holding the digest (default: sha256)",
    )
    args = parser.parse_args(argv)

    declaration = pathlib.Path(args.declaration)
    if not declaration.is_file():
        print(f"[verify] ERROR declaration not found: {declaration}", file=sys.stderr)
        return 2
    try:
        records = load_declarations(
            declaration, args.format, args.name_key, args.hash_key
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"[verify] ERROR cannot parse {declaration}: {exc}", file=sys.stderr)
        return 2
    if not records:
        print(f"[verify] ERROR no declarations found in {declaration}", file=sys.stderr)
        return 2

    root = pathlib.Path(args.root)
    failures, total = verify(records, root)
    if failures:
        for failure in failures:
            print(f"[verify] FAIL {failure}", file=sys.stderr)
        print(
            f"[verify] FAIL {len(failures)}/{total} declared artifact(s) did not match",
            file=sys.stderr,
        )
        return 1
    print(f"[verify] PASS {total}/{total} declared artifact(s) match recorded bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
