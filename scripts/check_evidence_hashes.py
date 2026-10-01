#!/usr/bin/env python3
"""Cross-check SHA256 declarations embedded in evidence documents.

Evidence packets mix several different kinds of digest: the current delivery
bytes, the pre-change baseline, superseded freeze values, and loose inline
references.  A naive text scraper cannot tell them apart and will either
miss a real defect or drown real defects in false positives.

This checker separates those cases:

* a current-state declaration with a resolvable path must match the file;
* a value that is the current freeze for the path, but was later replaced by
  a newer manifest, is reported as ``superseded`` rather than failed;
* a clearly historical value, a bare digest, or a digest with no path is
  reported without being treated as a pass.

Exit codes:
    0 = every current-state declaration matched, or no current-state claim
        existed and only historical/unresolved references were present
    1 = a current-state mismatch, missing file, or ambiguous path was found
    2 = usage or parse error
    3 = the document contained no current-state hash declaration
    4 = one or more current-state declarations could not be resolved

Exit 2, 3, and 4 are not passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from dataclasses import dataclass, field
from typing import Iterable


HEX64_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")
TABLE_CELL_RE = re.compile(r"^\s*\|.*\|\s*$")
TABLE_SEP_RE = re.compile(r"^\s*\|[\s:|-]+\|\s*$")
MARKDOWN_LINK_PATH_RE = re.compile(r"`([^`]+?\.(?:py|sh|md|json|jsonl|csv|txt|duckdb|db))`")

HISTORICAL_TERMS = (
    "改前",
    "旧值",
    "历史",
    "原值",
    "之前",
    "上一",
    "中间态",
    "失锚",
    "missing_frozen",
    "old",
    "before",
    "superseded",
)
CURRENT_TERMS = (
    "改后",
    "当前",
    "current",
    "最终",
    "交付态",
    "交付时",
    "现行",
    "new",
    "after",
    "final",
)
FIXED_LABELS = {
    "round1": "historical",
    "round2": "historical",
    "before": "historical",
    "after": "current",
    "current": "current",
    "final": "current",
}


@dataclass
class HashDeclaration:
    line_no: int
    digest: str
    raw_path: str | None
    state: str
    context: str
    source_kind: str = "inline"


@dataclass
class VerificationResult:
    document: str
    task_id: str = ""
    current: int = 0
    matched: list[dict] = field(default_factory=list)
    superseded: list[dict] = field(default_factory=list)
    historical: list[dict] = field(default_factory=list)
    mismatched: list[dict] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    ambiguous: list[dict] = field(default_factory=list)
    unresolved: list[dict] = field(default_factory=list)
    unresolved_current: int = 0
    parse_errors: list[str] = field(default_factory=list)
    declarations: int = 0

    def as_dict(self) -> dict:
        return {
            "document": self.document,
            "task_id": self.task_id,
            "counts": {
                "declarations": self.declarations,
                "current": self.current,
                "matched": len(self.matched),
                "superseded": len(self.superseded),
                "historical": len(self.historical),
                "mismatched": len(self.mismatched),
                "missing": len(self.missing),
                "ambiguous": len(self.ambiguous),
                "unresolved": len(self.unresolved),
                "unresolved_current": self.unresolved_current,
                "parse_errors": len(self.parse_errors),
            },
            "matched": self.matched,
            "superseded": self.superseded,
            "historical": self.historical,
            "mismatched": self.mismatched,
            "missing": self.missing,
            "ambiguous": self.ambiguous,
            "unresolved": self.unresolved,
            "parse_errors": self.parse_errors,
        }

    @property
    def failed(self) -> bool:
        return bool(self.mismatched or self.missing or self.ambiguous)

    @property
    def no_current_claim(self) -> bool:
        return self.current == 0


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _clean_path(raw: str) -> str | None:
    value = raw.strip().strip("`").strip()
    value = value.strip("`")
    value = re.sub(r"^[-*]\s+", "", value)
    value = value.split("#", 1)[0].strip()
    value = re.sub(r":\d+(?:-\d+)?$", "", value)
    value = value.rstrip(".,;:)]}>，。；：）】")
    value = value.lstrip("*").strip()
    if not value or value in {"-", "—", "N/A", "n/a"}:
        return None
    if "<" in value or ">" in value:
        return None
    if value.startswith("http://") or value.startswith("https://"):
        return None
    return value


def _paths_in_line(line: str) -> list[str]:
    paths: list[str] = []
    for match in MARKDOWN_LINK_PATH_RE.finditer(line):
        raw = _clean_path(match.group(1))
        if raw:
            paths.append(raw)
    for token in re.findall(r"(?<![\w./-])((?:sys-[^ \t`|]+|project-memory/[^ \t`|]+))", line):
        raw = _clean_path(token)
        if raw and raw not in paths:
            paths.append(raw)
    if not paths:
        for match in re.finditer(
            r"(?<![\w./-])([A-Za-z0-9_./-]+\.(?:py|sh|md|json|jsonl|csv|txt|duckdb|db))",
            line,
        ):
            raw = _clean_path(match.group(1))
            if raw and re.fullmatch(r"[0-9a-fA-F]{64}", pathlib.Path(raw).stem):
                continue
            if raw and raw not in paths:
                paths.append(raw)
    return paths


def _digest_in(line: str) -> list[str]:
    return [match.group(0).lower() for match in HEX64_RE.finditer(line)]


def _state_from_text(text: str, previous: str = "") -> str | None:
    combined = f"{text}\n{previous}"
    lowered = combined.lower()
    historical = any(term in combined or term in lowered for term in HISTORICAL_TERMS)
    current = any(term in combined or term in lowered for term in CURRENT_TERMS)
    if historical and current:
        return None
    if historical:
        return "historical"
    if current:
        return "current"
    return None


def _context_state(lines: list[str], index: int, max_back: int = 12) -> str | None:
    """Find the nearest explicit state before an opening code fence."""
    state = None
    for back in range(index, max(-1, index - max_back), -1):
        state = _state_from_text(lines[back])
        if state:
            return state
    return None


def _column_states(header: str) -> list[str] | None:
    if "|" not in header:
        return None
    cells = [cell.strip().strip("`") for cell in header.strip().strip("|").split("|")]
    lowered = [cell.lower() for cell in cells]
    before = next(
        (i for i, cell in enumerate(lowered) if "改前" in cell or "before" in cell),
        None,
    )
    after = next(
        (i for i, cell in enumerate(lowered) if "改后" in cell or "after" in cell),
        None,
    )
    if before is None or after is None:
        return None
    states = []
    for index in range(len(cells)):
        if index == before:
            states.append("historical")
        elif index == after:
            states.append("current")
        else:
            states.append("unresolved")
    return states


def _table_row(line: str) -> list[str]:
    return [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]


def _state_for_label(line: str) -> str | None:
    match = re.match(r"\s*([A-Za-z][A-Za-z0-9_-]*)\s*[:=]", line)
    if not match:
        return None
    return FIXED_LABELS.get(match.group(1).lower())


def _explicit_arrow_state(line: str) -> str | None:
    if "->" in line or "→" in line:
        return "current"
    return None


def parse_evidence(text: str) -> tuple[list[HashDeclaration], list[str]]:
    """Extract digest declarations and their current/historical intent."""
    declarations: list[HashDeclaration] = []
    errors: list[str] = []
    lines = text.splitlines()
    table_states: list[str] | None = None
    table_header_line = 0
    section_heading = ""
    block_state: str | None = None
    in_fence = False
    fence_marker: str | None = None

    for index, line in enumerate(lines):
        line_no = index + 1
        previous = lines[index - 1] if index else ""
        stripped = line.strip()
        fence = re.match(r"^\s*(```+|~~~+)", line)
        if fence:
            marker = fence.group(1)[0]
            if not in_fence:
                in_fence = True
                fence_marker = marker
                block_state = _context_state(lines, index)
            elif fence_marker == marker:
                in_fence = False
                fence_marker = None
                block_state = None
            continue
        if stripped.startswith("#"):
            section_heading = stripped
        if TABLE_SEP_RE.match(line):
            table_states = _column_states(lines[index - 1])
            table_header_line = line_no
            continue
        if not TABLE_CELL_RE.match(line):
            table_states = None
            table_header_line = 0

        digests = _digest_in(line)
        if not digests:
            continue

        default_state = block_state or _state_from_text(section_heading)
        local_state = _state_from_text(line, previous)
        if local_state is None:
            local_state = default_state

        if table_states and len(_table_row(line)) == len(table_states):
            cells = _table_row(line)
            cell_digests: list[tuple[int, str]] = []
            for cell_index, cell in enumerate(cells):
                for digest in _digest_in(cell):
                    cell_digests.append((cell_index, digest))
            row_paths = _paths_in_line(line)
            for cell_index, digest in cell_digests:
                state = table_states[cell_index]
                declarations.append(
                    HashDeclaration(
                        line_no=line_no,
                        digest=digest,
                        raw_path=row_paths[0] if row_paths else None,
                        state=state,
                        context=f"table header line {table_header_line}",
                        source_kind="table",
                    )
                )
            continue

        paths = _paths_in_line(line)
        if len(digests) >= 2 and ("->" in line or "→" in line):
            inherited = block_state or _state_from_text(section_heading)
            if inherited == "historical":
                old_state, new_state = "historical", "historical"
            else:
                old_state, new_state = "historical", "current"
            declarations.append(
                HashDeclaration(
                    line_no=line_no,
                    digest=digests[-1],
                    raw_path=paths[0] if paths else None,
                    state=new_state,
                    context=line.strip(),
                    source_kind="arrow",
                )
            )
            declarations.append(
                HashDeclaration(
                    line_no=line_no,
                    digest=digests[0],
                    raw_path=paths[0] if paths else None,
                    state=old_state,
                    context=line.strip(),
                    source_kind="arrow",
                )
            )
            continue

        # sha256sum-style lines always carry a path.  Resolve it even when
        # the surrounding heading does not say whether the value is current.
        if len(digests) == 1 and paths:
            declarations.append(
                HashDeclaration(
                    line_no=line_no,
                    digest=digests[0],
                    raw_path=paths[0],
                    state=local_state or ("current" if block_state is None else block_state),
                    context=line.strip(),
                    source_kind="manifest-line",
                )
            )
            continue

        label_state = _state_for_label(line)
        arrow_state = _explicit_arrow_state(line)
        if arrow_state:
            state = arrow_state
        elif label_state:
            state = label_state
        else:
            state = local_state or "unresolved"

        # Key-value forms such as ``sha256: <digest>``.  The path is the
        # nearest path on the same line, or the previous non-empty line.
        if re.match(r"\s*(sha256|sha-?256|hash|digest)\s*[:=]", line, re.I):
            raw_path = paths[0] if paths else None
            if raw_path is None:
                for back in range(index - 1, max(-1, index - 4), -1):
                    candidate = _paths_in_line(lines[back])
                    if candidate:
                        raw_path = candidate[0]
                        break
            declarations.append(
                HashDeclaration(
                    line_no=line_no,
                    digest=digests[0],
                    raw_path=raw_path,
                    state=state if state != "unresolved" else "unresolved",
                    context="key-value digest",
                    source_kind="key-value",
                )
            )
            continue

        for digest_index, digest in enumerate(digests):
            raw_path = paths[digest_index] if len(paths) > digest_index else None
            if raw_path is None and len(digests) == 1 and len(paths) == 1:
                raw_path = paths[0]
            declarations.append(
                HashDeclaration(
                    line_no=line_no,
                    digest=digest,
                    raw_path=raw_path,
                    state=state,
                    context=line.strip(),
                    source_kind="inline",
                )
            )

    return declarations, errors


def load_manifest_chain(workspace: pathlib.Path) -> list[tuple[str, str, str]]:
    """Return ``(task_id, digest, path)`` entries in task-id order."""
    manifest_dir = workspace / "sys-agents" / "manifests"
    entries: list[tuple[str, str, str]] = []
    if not manifest_dir.is_dir():
        return entries
    for manifest in sorted(manifest_dir.glob("*.sha256")):
        task_id = manifest.stem
        for line_no, line in enumerate(
            manifest.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            match = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", line)
            if not match:
                continue
            entries.append((task_id, match.group(1).lower(), match.group(2).strip()))
    return entries


def manifest_membership(
    entries: Iterable[tuple[str, str, str]],
) -> tuple[dict[tuple[str, str], list[str]], dict[str, list[tuple[str, str]]]]:
    """Index manifests by path/hash and by hash alone.

    A path/hash pair proves a value was frozen somewhere.  A hash-only match
    is weaker evidence: it catches old values in documents whose path moved,
    but must be disclosed as such.
    """
    by_pair: dict[tuple[str, str], list[str]] = {}
    for task_id, digest, path in entries:
        by_pair.setdefault((path, digest), []).append(task_id)
    by_hash: dict[str, list[tuple[str, str]]] = {}
    for task_id, digest, path in entries:
        by_hash.setdefault(digest, []).append((task_id, path))
    return by_pair, by_hash


def latest_manifest_for_path(
    path: str, by_hash: dict[str, list[tuple[str, str]]]
) -> tuple[str, str] | None:
    """Return the newest manifest entry for a path.

    Task ids sort chronologically in this workspace.  When a path appears in
    multiple manifests, the newest one is the current freeze; older values
    are history and must not be reported as current mismatches.
    """
    candidates: list[tuple[str, str]] = []
    for digest, entries in by_hash.items():
        for task_id, entry_path in entries:
            if entry_path == path:
                candidates.append((task_id, digest))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])


def resolve_paths(
    raw_path: str,
    workspace: pathlib.Path,
    evidence_text: str,
) -> list[pathlib.Path]:
    """Resolve an evidence path, searching known roots when it is a basename."""
    if not raw_path:
        return []
    candidate = pathlib.Path(raw_path)
    if candidate.is_absolute():
        return [candidate] if candidate.is_file() else []
    direct = workspace / candidate
    if direct.is_file():
        return [direct]

    if candidate.parent != pathlib.Path("."):
        return []
    basename = candidate.name
    contextual = {
        path
        for path in _paths_in_line(evidence_text)
        if pathlib.Path(path).name == basename
        and "_trash" not in pathlib.Path(path).parts
        and "_superseded" not in pathlib.Path(path).parts
    }
    if contextual:
        resolved: list[pathlib.Path] = []
        for raw in contextual:
            candidate = pathlib.Path(raw)
            if not candidate.is_absolute():
                candidate = workspace / candidate
            if candidate.is_file() and candidate not in resolved:
                resolved.append(candidate)
        if resolved:
            current = [
                path
                for path in resolved
                if "_trash" not in path.parts and "_superseded" not in path.parts
            ]
            return current or resolved
    roots = (
        workspace,
        workspace / "sys-scripts",
        workspace / "sys-agents" / "tasks",
        workspace / "sys-agents" / "templates",
        workspace / "sys-data",
        workspace / "sys-deals",
        workspace / "project-memory",
    )
    for root in roots:
        if not root.is_dir():
            continue
        for parent in (root, *root.glob("*")):
            candidate = parent / basename
            if candidate.is_file():
                return [candidate]
    matches: list[pathlib.Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        for found in root.rglob(basename):
            found = found.resolve()
            if found.is_file() and found not in matches:
                # Avoid generated/cache trees and old superseded manifests.
                if any(part in {"__pycache__", "_trash", "node_modules", ".git"} for part in found.parts):
                    continue
                matches.append(found)
    return matches


def _manifest_status(
    digest: str,
    raw_path: str,
    by_pair: dict[tuple[str, str], list[str]],
    by_hash: dict[str, list[tuple[str, str]]],
    document_task_id: str,
) -> tuple[str, list[str]]:
    if not raw_path:
        return "unresolved", []
    task_ids = by_pair.get((raw_path, digest))
    if task_ids:
        latest = latest_manifest_for_path(raw_path, by_hash)
        if latest and latest[1] != digest:
            if document_task_id and document_task_id < latest[0]:
                return "superseded", sorted(set(task_ids) | {latest[0]})
            return "stale", sorted(set(task_ids) | {latest[0]})
        return "frozen-current", sorted(set(task_ids))
    hash_entries = by_hash.get(digest)
    if hash_entries:
        return "hash-only", sorted({task_id for task_id, _ in hash_entries})
    latest = latest_manifest_for_path(raw_path, by_hash)
    if latest and document_task_id and document_task_id < latest[0]:
        return "superseded", [latest[0]]
    return "not-frozen", []


def task_id_from_text(text: str) -> str:
    match = re.search(r"^task_id:\s*(\S+)", text, re.M)
    if match:
        return match.group(1).strip()
    match = re.search(r"\b(TASK-\d{8}-\d{3})\b", text)
    return match.group(1) if match else ""


def verify_document(
    document: pathlib.Path,
    workspace: pathlib.Path,
    manifests: list[tuple[str, str, str]],
) -> VerificationResult:
    text = document.read_text(encoding="utf-8", errors="replace")
    declarations, errors = parse_evidence(text)
    task_id = task_id_from_text(text)
    result = VerificationResult(
        document=str(document), task_id=task_id, parse_errors=errors
    )
    result.declarations = len(declarations)
    by_pair, by_hash = manifest_membership(manifests)

    for declaration in declarations:
        record = {
            "line": declaration.line_no,
            "digest": declaration.digest,
            "path": declaration.raw_path,
            "state": declaration.state,
            "source": declaration.source_kind,
            "context": declaration.context,
        }
        if declaration.state == "historical":
            result.historical.append(record)
            continue
        if declaration.state == "unresolved" or not declaration.raw_path:
            result.unresolved.append(record)
            continue

        result.current += 1
        status, manifest_ids = _manifest_status(
            declaration.digest,
            declaration.raw_path,
            by_pair,
            by_hash,
            task_id,
        )
        record["manifest_status"] = status
        if manifest_ids:
            record["manifest_task_ids"] = manifest_ids

        paths = resolve_paths(declaration.raw_path, workspace, text)
        if not paths:
            explicit_path = declaration.raw_path and "/" in declaration.raw_path
            if status in {"superseded", "stale"} or not explicit_path:
                record["reason"] = "declared in a manifest but no file resolved"
                if status == "stale":
                    result.mismatched.append(record)
                else:
                    result.superseded.append(record)
            else:
                record["reason"] = "current declaration points to a missing file"
                result.missing.append(record)
            continue
        if len(paths) > 1:
            record["candidates"] = [str(path) for path in paths]
            result.ambiguous.append(record)
            result.unresolved_current += 1
            continue
        try:
            resolved_rel = str(paths[0].resolve().relative_to(workspace.resolve()))
        except ValueError:
            resolved_rel = ""
        if resolved_rel and resolved_rel != declaration.raw_path:
            resolved_status, resolved_ids = _manifest_status(
                declaration.digest,
                resolved_rel,
                by_pair,
                by_hash,
                task_id,
            )
            if resolved_status != "not-frozen":
                status, manifest_ids = resolved_status, resolved_ids
                record["manifest_status"] = status
                record["resolved_manifest_path"] = resolved_rel
                if manifest_ids:
                    record["manifest_task_ids"] = manifest_ids
        actual = sha256_file(paths[0])
        record["resolved"] = str(paths[0])
        record["actual"] = actual
        if actual == declaration.digest:
            result.matched.append(record)
        elif status in {"superseded", "stale"}:
            record["reason"] = "the declared value is an older manifest freeze"
            if status == "stale":
                record["reason"] = (
                    "document declares a stale current value; a newer manifest "
                    "freeze exists for the same path"
                )
                result.mismatched.append(record)
            else:
                result.superseded.append(record)
        else:
            result.mismatched.append(record)

    return result


def discover_documents(paths: list[pathlib.Path]) -> list[pathlib.Path]:
    documents: list[pathlib.Path] = []
    for path in paths:
        if path.is_dir():
            documents.extend(sorted(path.glob("*-evidence.md")))
        else:
            documents.append(path)
    return documents


def print_text(result: VerificationResult) -> None:
    counts = result.as_dict()["counts"]
    print(
        f"[evidence] {result.document}: "
        f"current={counts['current']} matched={counts['matched']} "
        f"superseded={counts['superseded']} historical={counts['historical']} "
        f"mismatched={counts['mismatched']} missing={counts['missing']} "
        f"ambiguous={counts['ambiguous']} unresolved={counts['unresolved']}"
    )
    for item in result.mismatched:
        print(
            f"[evidence] FAIL mismatch line {item['line']}: {item['path']}\n"
            f"  declared={item['digest']}\n"
            f"  actual  ={item['actual']}"
        )
    for item in result.missing:
        print(f"[evidence] FAIL missing line {item['line']}: {item['path']}")
    for item in result.ambiguous:
        print(
            f"[evidence] FAIL ambiguous line {item['line']}: {item['path']} "
            f"({len(item['candidates'])} candidates)"
        )
    for item in result.unresolved:
        if item.get("reason"):
            print(
                f"[evidence] UNRESOLVED line {item['line']}: "
                f"{item['path'] or '<no path>'} ({item['reason']})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="verify SHA256 declarations embedded in evidence documents"
    )
    parser.add_argument("documents", nargs="*", help="evidence Markdown files or directories")
    parser.add_argument(
        "--workspace",
        default=".",
        help="workspace root used for relative paths and manifest discovery",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit machine-readable JSON instead of text",
    )
    args = parser.parse_args(argv)

    workspace = pathlib.Path(args.workspace).resolve()
    if not workspace.is_dir():
        print(f"[evidence] ERROR workspace not found: {workspace}", file=sys.stderr)
        return 2

    raw_documents = [pathlib.Path(item) for item in args.documents]
    if not raw_documents:
        default_dir = workspace / "sys-agents" / "tasks"
        raw_documents = [default_dir]
    documents = discover_documents(raw_documents)
    if not documents:
        print("[evidence] ERROR no evidence documents found", file=sys.stderr)
        return 2

    missing_docs = [str(path) for path in documents if not path.is_file()]
    if missing_docs:
        for path in missing_docs:
            print(f"[evidence] ERROR document not found: {path}", file=sys.stderr)
        return 2

    manifests = load_manifest_chain(workspace)
    results: list[VerificationResult] = []
    for document in documents:
        try:
            results.append(verify_document(document, workspace, manifests))
        except (OSError, ValueError) as exc:
            print(f"[evidence] ERROR cannot read {document}: {exc}", file=sys.stderr)
            return 2

    if args.json:
        payload = [result.as_dict() for result in results]
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        for result in results:
            print_text(result)

    if any(result.parse_errors for result in results):
        return 2
    if any(result.failed for result in results):
        return 1
    if any(result.unresolved_current for result in results):
        if not args.json:
            print(
                "[evidence] UNRESOLVED: current-state declarations need paths "
                "before they can be verified",
                file=sys.stderr,
            )
        return 4
    if all(result.no_current_claim for result in results):
        if not args.json:
            print("[evidence] NO CURRENT CLAIMS: nothing was verified", file=sys.stderr)
        return 3
    if not args.json:
        total = sum(result.current for result in results)
        matched = sum(len(result.matched) for result in results)
        print(f"[evidence] PASS {matched}/{total} current declaration(s) matched")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
