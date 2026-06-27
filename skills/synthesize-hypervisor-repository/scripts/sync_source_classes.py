#!/usr/bin/env python3
"""Synchronize S08 source presentation metadata with function-map.

Semantic rewrite and naming passes intentionally mutate function-map,
source-map, and user-facing source files in multiple batches.  If a later pass
is interrupted or only updates part of the model, S09 should fail instead of
silently packaging drifted evidence.  This helper is the deterministic S08
repair step: function-map remains authoritative for output_class/confidence and
the source-map plus source evidence comments are rewritten to match it.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
FUNC_DEF_RE_TEMPLATE = r"(^|\n)uintptr_t\s+{symbol}\s*\(\s*struct\s+recovered_context\s+\*ctx\s*\)"
EVIDENCE_RE = re.compile(
    r"/\* evidence: image offset (?P<addr>0x[0-9a-fA-F]+), "
    r"IDA (?P<ida>[^,]+), range (?P<range>[^,]+), "
    r"confidence (?P<confidence>[^,]+), class (?P<class>[a-zA-Z0-9_-]+) \*/"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def rel(path: Path) -> str:
    return path.as_posix()


def load_paths(case_id: str) -> dict[str, Path]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    delivery = read_json(s08 / "source-repo-delivery.json")
    return {
        "case": case,
        "s08": s08,
        "repo": ROOT / delivery["canonical_source_repo"],
        "function_map": s08 / "function-map.json",
        "source_map": s08 / "source-map.json",
        "delivery": s08 / "source-repo-delivery.json",
    }


def replace_nearest_evidence_comment(
    text: str,
    symbol: str,
    expected_addr: str,
    expected_ida: str,
    expected_range: str,
    expected_class: str,
    expected_confidence: str,
) -> tuple[str, dict[str, Any] | None]:
    """Replace evidence metadata nearest to a function definition."""

    func_re = re.compile(FUNC_DEF_RE_TEMPLATE.format(symbol=re.escape(symbol)))
    func_match = func_re.search(text)
    if not func_match:
        return text, {
            "changed": False,
            "kind": "source_function_not_found",
            "symbol": symbol,
        }

    prefix = text[: func_match.start()]
    comments = list(EVIDENCE_RE.finditer(prefix))
    canonical_comment = (
        f"/* evidence: image offset {expected_addr}, IDA {expected_ida}, "
        f"range {expected_range}, confidence {expected_confidence}, class {expected_class} */"
    )
    if not comments:
        insert_at = func_match.start()
        new_text = text[:insert_at] + canonical_comment + "\n" + text[insert_at:]
        return text, {
            "changed": True,
            "kind": "source_evidence_comment_inserted",
            "symbol": symbol,
        } | {"new_text": new_text}

    comment = comments[-1]
    old_addr = comment.group("addr").lower()
    old_class = comment.group("class")
    old_confidence = comment.group("confidence")
    if old_addr == expected_addr.lower() and old_class == expected_class and old_confidence == expected_confidence:
        return text, None

    if old_addr != expected_addr.lower():
        insert_at = func_match.start()
        new_text = text[:insert_at] + canonical_comment + "\n" + text[insert_at:]
        return new_text, {
            "changed": True,
            "kind": "source_evidence_comment_inserted_for_address_mismatch",
            "symbol": symbol,
            "old_address": old_addr,
            "new_address": expected_addr,
            "old_output_class": old_class,
            "new_output_class": expected_class,
            "old_confidence": old_confidence,
            "new_confidence": expected_confidence,
        }

    new_text = text[: comment.start()] + canonical_comment + text[comment.end() :]
    return new_text, {
        "changed": True,
        "kind": "source_evidence_metadata_synced",
        "symbol": symbol,
        "address": expected_addr,
        "old_output_class": old_class,
        "new_output_class": expected_class,
        "old_confidence": old_confidence,
        "new_confidence": expected_confidence,
    }


def refresh_file_sizes(obj: dict[str, Any], repo: Path) -> None:
    files = obj.get("files") or obj.get("source_files")
    if not isinstance(files, list):
        return
    for row in files:
        path = repo / row.get("path", "")
        if path.exists() and path.is_file():
            row["size"] = path.stat().st_size


def sync(case_id: str) -> dict[str, Any]:
    paths = load_paths(case_id)
    s08 = paths["s08"]
    repo = paths["repo"]
    function_map = read_json(paths["function_map"])
    source_map = read_json(paths["source_map"])
    delivery = read_json(paths["delivery"])

    functions = function_map.get("functions", [])
    source_entries = source_map.get("function_sources", [])
    source_by_addr = {str(row.get("function", "")).lower(): row for row in source_entries}

    rows: list[dict[str, Any]] = []
    source_cache: dict[str, str] = {}
    source_changed: set[str] = set()
    map_updates = 0
    comment_updates = 0
    warnings = 0

    for fn in functions:
        addr = str(fn.get("address", "")).lower()
        if not addr:
            continue
        expected_class = str(fn.get("output_class", "lifted-c"))
        expected_confidence = str(fn.get("confidence", "medium"))
        expected_symbol = str(fn.get("source_symbol", ""))
        expected_source = str(fn.get("source_file", ""))
        expected_ida = str(fn.get("ida_name", "unknown"))
        start, end = fn.get("range", [addr, fn.get("end", addr)])
        expected_range = f"{start}-{end}"
        mapping = source_by_addr.get(addr)
        if not mapping:
            rows.append(
                {
                    "address": addr,
                    "changed": False,
                    "kind": "missing_source_map_entry",
                    "expected_output_class": expected_class,
                }
            )
            warnings += 1
            continue

        map_changed_fields: dict[str, list[Any]] = {}
        if mapping.get("output_class") != expected_class:
            map_changed_fields["output_class"] = [mapping.get("output_class"), expected_class]
            mapping["output_class"] = expected_class
        if expected_symbol and mapping.get("symbol") != expected_symbol:
            map_changed_fields["symbol"] = [mapping.get("symbol"), expected_symbol]
            mapping["symbol"] = expected_symbol
        if expected_source and mapping.get("source") != expected_source:
            map_changed_fields["source"] = [mapping.get("source"), expected_source]
            mapping["source"] = expected_source
        if fn.get("semantic_name") and mapping.get("semantic_name") != fn.get("semantic_name"):
            map_changed_fields["semantic_name"] = [mapping.get("semantic_name"), fn.get("semantic_name")]
            mapping["semantic_name"] = fn.get("semantic_name")
        if map_changed_fields:
            map_updates += 1
            rows.append(
                {
                    "address": addr,
                    "changed": True,
                    "kind": "source_map_synced",
                    "fields": map_changed_fields,
                    "source": mapping.get("source"),
                    "symbol": mapping.get("symbol"),
                }
            )

        source_file = str(mapping.get("source", ""))
        symbol = str(mapping.get("symbol", ""))
        if not source_file or not symbol:
            rows.append(
                {
                    "address": addr,
                    "changed": False,
                    "kind": "source_or_symbol_missing_after_map_sync",
                    "source": source_file,
                    "symbol": symbol,
                }
            )
            warnings += 1
            continue

        source_path = repo / source_file
        if not source_path.exists():
            rows.append(
                {
                    "address": addr,
                    "changed": False,
                    "kind": "source_file_not_found",
                    "source": source_file,
                    "symbol": symbol,
                }
            )
            warnings += 1
            continue

        if source_file not in source_cache:
            source_cache[source_file] = source_path.read_text(encoding="utf-8", errors="replace")
        new_text, comment_row = replace_nearest_evidence_comment(
            source_cache[source_file],
            symbol,
            addr,
            expected_ida,
            expected_range,
            expected_class,
            expected_confidence,
        )
        if comment_row and "new_text" in comment_row:
            new_text = comment_row.pop("new_text")
        if comment_row:
            comment_row.update(
                {
                    "address": addr,
                    "source": source_file,
                    "expected_output_class": expected_class,
                    "expected_confidence": expected_confidence,
                }
            )
            rows.append(comment_row)
            if comment_row.get("changed"):
                comment_updates += 1
                source_cache[source_file] = new_text
                source_changed.add(source_file)
            else:
                warnings += 1

    for source_file in sorted(source_changed):
        path = repo / source_file
        path.write_text(source_cache[source_file], encoding="utf-8", newline="\n")

    refresh_file_sizes(source_map, repo)
    refresh_file_sizes(delivery, repo)
    write_json(paths["source_map"], source_map)
    write_json(paths["delivery"], delivery)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-SOURCE-CLASS-SYNC-RW1",
        "generated_at": now_iso(),
        "status": "source_class_sync_complete" if warnings == 0 else "source_class_sync_complete_with_warnings",
        "canonical_source_repo": rel(repo.relative_to(ROOT)),
        "function_count": len(functions),
        "source_map_updates": map_updates,
        "source_comment_updates": comment_updates,
        "source_files_updated": len(source_changed),
        "warning_count": warnings,
        "policy": "function-map is authoritative for output_class/confidence; source-map and source evidence comments must agree before S09/S10.",
    }
    write_json(s08 / "source-class-sync-summary.json", summary)
    write_jsonl(s08 / "source-class-sync-index.jsonl", rows)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    print(json.dumps(sync(args.case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
