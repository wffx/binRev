#!/usr/bin/env python3
"""Repair source-map symbols that disappeared from source files.

This is a conservative recovery tool for failed organization passes.  It reads
S09 findings for `mapped_symbol_not_found_in_source` and re-inserts a minimal
evidence-backed wrapper into the mapped source file.  It does not change names,
classes, or function-map semantics.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def source_has_symbol(text: str, symbol: str) -> bool:
    return bool(re.search(r"(^|\n)uintptr_t\s+" + re.escape(symbol) + r"\s*\(", text))


def wrapper(fn: dict[str, Any], symbol: str) -> str:
    mark = {
        "semantic-c": "recovered_mark_semantic",
        "lifted-c": "recovered_mark_lifted",
        "asm-fallback": "recovered_mark_asm_fallback",
    }.get(fn.get("output_class"), "recovered_mark_lifted")
    addr = fn["address"].lower()
    start, end = fn.get("range", [addr, addr])
    return f"""
/* evidence: image offset {addr}, IDA {fn.get('ida_name')}, range {start}-{end}, confidence {fn.get('confidence', 'medium')}, class {fn.get('output_class', 'lifted-c')} */
/* source-symbol repair: original source block was missing; restored conservative wrapper from S08 function-map. */
uintptr_t {symbol}(struct recovered_context *ctx)
{{
    /* evidence: original IDA name {fn.get('ida_name')}, image offset {addr} */
    {mark}(ctx);
    recovered_trace(ctx, \"{symbol}\", {addr}ULL);
    return 0;
}}
"""


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


def scan_existing_repairs(repo: Path, fmap: dict[str, Any], smap: dict[str, Any]) -> list[dict[str, Any]]:
    fn_by_symbol = {fn.get("source_symbol"): fn for fn in fmap.get("functions", [])}
    source_by_symbol = {
        (entry.get("symbol") or entry.get("source_symbol")): entry.get("source")
        for entry in smap.get("function_sources", [])
    }
    rows: list[dict[str, Any]] = []
    pattern = re.compile(
        r"/\* source-symbol repair: original source block was missing; restored conservative wrapper from S08 function-map\. \*/\n"
        r"uintptr_t\s+(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*\(",
        flags=re.MULTILINE,
    )
    for path in sorted(repo.rglob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(repo).as_posix()
        for match in pattern.finditer(text):
            symbol = match.group("symbol")
            fn = fn_by_symbol.get(symbol)
            rows.append(
                {
                    "address": fn.get("address") if fn else None,
                    "source": source_by_symbol.get(symbol, rel),
                    "symbol": symbol,
                    "repaired": True,
                    "reason": "repair_block_present_in_source",
                    "output_class": fn.get("output_class") if fn else None,
                    "confidence": fn.get("confidence") if fn else None,
                }
            )
    return rows


def repair(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    s09 = case / "stages" / "S09"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    fmap = read_json(s08 / "function-map.json")
    smap = read_json(s08 / "source-map.json")
    delivery = read_json(s08 / "source-repo-delivery.json")
    quality = read_json(s08 / "source-quality-report.json")
    fn_by_addr = {fn["address"].lower(): fn for fn in fmap.get("functions", [])}

    findings = [
        row
        for row in read_jsonl(s09 / "audit-findings.jsonl")
        if row.get("kind") == "mapped_symbol_not_found_in_source"
    ]
    rows: list[dict[str, Any]] = []
    by_file: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        by_file.setdefault(finding["source"], []).append(finding)

    repaired = 0
    skipped = 0
    for source, file_findings in by_file.items():
        path = repo / source
        if not path.exists():
            skipped += len(file_findings)
            for f in file_findings:
                rows.append({**f, "repaired": False, "reason": "source_file_missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        additions: list[str] = []
        for finding in file_findings:
            symbol = finding["symbol"]
            addr = finding["address"].lower()
            if source_has_symbol(text, symbol):
                rows.append({**finding, "repaired": False, "reason": "symbol_already_present"})
                skipped += 1
                continue
            fn = fn_by_addr.get(addr)
            if not fn:
                rows.append({**finding, "repaired": False, "reason": "function_map_missing"})
                skipped += 1
                continue
            additions.append(wrapper(fn, symbol))
            rows.append(
                {
                    **finding,
                    "repaired": True,
                    "reason": "restored_wrapper_from_function_map",
                    "output_class": fn.get("output_class"),
                    "confidence": fn.get("confidence"),
                }
            )
            repaired += 1
        if additions:
            path.write_text(text.rstrip() + "\n\n/* source-symbol repair block */\n" + "\n".join(additions) + "\n", encoding="utf-8", newline="\n")

    refresh_source_files(repo, smap, delivery, quality)
    quality["source_symbol_repair_policy"] = "Repairs restore missing mapped symbols as conservative wrappers; they do not promote output_class."
    write_json(s08 / "source-map.json", smap)
    write_json(s08 / "source-repo-delivery.json", delivery)
    write_json(s08 / "source-quality-report.json", quality)

    scan_rows = scan_existing_repairs(repo, fmap, smap)
    by_key: dict[tuple[str | None, str], dict[str, Any]] = {}
    for row in rows + scan_rows:
        by_key[(row.get("address"), row.get("symbol", ""))] = row
    merged_rows = list(by_key.values())

    enriched = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-SOURCE-SYMBOL-REPAIR-RW1",
            "generated_at": now_iso(),
            "boundary": "Coverage repair only; no semantic body recovery.",
        }
        for row in merged_rows
    ]
    write_jsonl(s08 / "source-symbol-repair-index.jsonl", enriched)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-SOURCE-SYMBOL-REPAIR-RW1",
        "repaired": repaired,
        "skipped": skipped,
        "finding_count": len(findings),
        "repair_blocks_present": len(scan_rows),
        "index_rows": len(enriched),
        "boundary": "Restored missing mapped source symbols from function-map wrappers.",
    }
    write_json(s08 / "source-symbol-repair-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    print(json.dumps(repair(args.case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
