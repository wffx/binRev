#!/usr/bin/env python3
"""Remove duplicate source functions that live in the wrong source file.

This is a conservative S08 repair for source-organization regressions.  It
uses S08/function-map.json as the authority for each primary source symbol's
canonical source_file.  If the same symbol is defined in multiple .c files, a
definition is removed only when:

- the file is not the function-map source_file; and
- the canonical file already contains the same symbol.

The removal starts at the nearest preceding evidence comment for that wrapper,
so lifted pseudocode review blocks that belong to the duplicate function are
removed together with the duplicate compiled wrapper.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
FUNC_DEF_RE = re.compile(r"^uintptr_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
EVIDENCE_RE = re.compile(r"/\* evidence: image offset 0x[0-9a-fA-F]+, IDA ")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def source_has_symbol(text: str, symbol: str) -> bool:
    return bool(re.search(r"(^|\n)uintptr_t\s+" + re.escape(symbol) + r"\s*\(", text))


def find_function_end(text: str, def_start: int) -> int:
    brace = text.find("{", def_start)
    if brace < 0:
        return def_start
    depth = 0
    idx = brace
    while idx < len(text):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                idx += 1
                while idx < len(text) and text[idx] in " \t\r\n":
                    idx += 1
                return idx
        idx += 1
    return len(text)


def find_block_start(text: str, def_start: int) -> int:
    matches = list(EVIDENCE_RE.finditer(text, 0, def_start))
    if not matches:
        return text.rfind("\n", 0, def_start) + 1
    start = matches[-1].start()
    while start > 0 and text[start - 1] in "\r\n":
        start -= 1
    return start


def scan_defs(repo: Path) -> dict[str, list[dict[str, Any]]]:
    defs: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in sorted(repo.rglob("*.c")):
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in FUNC_DEF_RE.finditer(text):
            defs[match.group(1)].append({"source": rel, "offset": match.start()})
    return defs


def refresh_source_files(repo: Path, smap: dict[str, Any], delivery: dict[str, Any], quality: dict[str, Any]) -> None:
    files = [
        {"path": p.relative_to(repo).as_posix(), "size": p.stat().st_size}
        for p in sorted(repo.rglob("*"))
        if p.is_file()
    ]
    smap["source_files"] = files
    delivery["files"] = files
    delivery["contains_c"] = any(row["path"].endswith(".c") for row in files)
    delivery["contains_h"] = any(row["path"].endswith(".h") for row in files)
    delivery["forbidden_artifact_count"] = sum(
        1 for row in files if Path(row["path"]).suffix.lower() in {".json", ".jsonl", ".sqlite", ".i64", ".idb"}
    )
    quality["source_files"] = len(files)


def repair(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    fmap = read_json(s08 / "function-map.json")
    smap = read_json(s08 / "source-map.json")
    delivery = read_json(s08 / "source-repo-delivery.json")
    quality = read_json(s08 / "source-quality-report.json")

    canonical_by_symbol = {
        fn["source_symbol"]: fn["source_file"]
        for fn in fmap.get("functions", [])
        if fn.get("source_symbol") and fn.get("source_file")
    }
    defs_by_symbol = scan_defs(repo)
    text_cache = {p.relative_to(repo).as_posix(): p.read_text(encoding="utf-8", errors="replace") for p in repo.rglob("*.c")}

    removals_by_file: dict[str, list[tuple[int, int, str, str]]] = defaultdict(list)
    rows: list[dict[str, Any]] = []
    removed_blocks: list[dict[str, Any]] = []
    skipped = 0
    for symbol, defs in defs_by_symbol.items():
        if len(defs) < 2:
            continue
        canonical = canonical_by_symbol.get(symbol)
        if not canonical:
            skipped += len(defs)
            continue
        canonical_text = text_cache.get(canonical, "")
        if not source_has_symbol(canonical_text, symbol):
            skipped += len(defs)
            continue
        for item in defs:
            source = item["source"]
            if source == canonical:
                continue
            text = text_cache[source]
            start = find_block_start(text, item["offset"])
            end = find_function_end(text, item["offset"])
            removals_by_file[source].append((start, end, symbol, canonical))

    removed = 0
    for source, ranges in removals_by_file.items():
        path = repo / source
        text = text_cache[source]
        new_text = text
        for start, end, symbol, canonical in sorted(ranges, reverse=True):
            removed_block = new_text[start:end]
            new_text = new_text[:start].rstrip() + "\n\n" + new_text[end:].lstrip()
            rows.append(
                {
                    "case_id": case_id,
                    "stage_id": "S08",
                    "iteration_id": "S08-DUPLICATE-WRONG-FILE-CLEANUP-RW1",
                    "generated_at": now_iso(),
                    "symbol": symbol,
                    "removed_from": source,
                    "canonical_source": canonical,
                    "reason": "duplicate_definition_in_noncanonical_source_file",
                    "boundary": "Source organization repair only; function-map/source-map semantics unchanged.",
                }
            )
            removed_blocks.append(
                {
                    "case_id": case_id,
                    "stage_id": "S08",
                    "iteration_id": "S08-DUPLICATE-WRONG-FILE-CLEANUP-RW1",
                    "generated_at": now_iso(),
                    "symbol": symbol,
                    "removed_from": source,
                    "canonical_source": canonical,
                    "removed_block": removed_block,
                    "boundary": "Archived removed noncanonical duplicate block for audit only; not part of the source repository.",
                }
            )
            removed += 1
        path.write_text(new_text.rstrip() + "\n", encoding="utf-8", newline="\n")

    refresh_source_files(repo, smap, delivery, quality)
    quality["duplicate_wrong_file_cleanup_policy"] = (
        "Duplicate function definitions outside function-map source_file are removed only when the canonical source already contains the symbol."
    )
    write_json(s08 / "source-map.json", smap)
    write_json(s08 / "source-repo-delivery.json", delivery)
    write_json(s08 / "source-quality-report.json", quality)
    write_jsonl(s08 / "duplicate-wrong-file-cleanup-index.jsonl", rows)
    write_jsonl(s08 / "duplicate-wrong-file-removed-blocks.jsonl", removed_blocks)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-DUPLICATE-WRONG-FILE-CLEANUP-RW1",
        "removed": removed,
        "skipped": skipped,
        "affected_files": sorted(removals_by_file),
        "boundary": "Removed duplicate definitions from noncanonical source files only.",
    }
    write_json(s08 / "duplicate-wrong-file-cleanup-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    print(json.dumps(repair(args.case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
