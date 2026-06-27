#!/usr/bin/env python3
"""Apply a conservative semantic rewrite batch to corpus-lifted source.

This S08 helper rewrites only simple, evidence-backed Hex-Rays patterns:

- return constant;
- return global object;
- return direct sub_xxx call;
- return indirect off_/qword_/dword_ call.

It intentionally skips complex expressions and control flow. The goal is to
replace generic wrapper bodies with small readable bodies only when the
decompiler evidence is trivial enough to preserve without invention.
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


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def normalize_addr(addr: str) -> str:
    return hex(int(addr, 16))


def source_symbol_for_sub(call_name: str, addr_to_symbol: dict[str, str]) -> str | None:
    m = re.fullmatch(r"sub_([0-9A-Fa-f]+)", call_name)
    if not m:
        return None
    return addr_to_symbol.get(hex(int(m.group(1), 16)))


def classify_simple_return(lines: list[str], addr_to_symbol: dict[str, str]) -> dict[str, Any] | None:
    inner = [line.strip() for line in lines[2:-1] if line.strip()]
    if len(inner) != 1:
        return None
    stmt = inner[0]

    m = re.fullmatch(r"return\s+(0x[0-9A-Fa-f]+|-?\d+);", stmt)
    if m:
        value = m.group(1)
        if value.startswith("-"):
            expr = f"(uintptr_t)(intptr_t){value}"
        elif value.startswith("0x"):
            expr = f"{value}ULL"
        else:
            expr = f"{value}ULL"
        return {"kind": "return_constant", "statement": stmt, "body_return": expr}

    m = re.fullmatch(r"return\s+((?:qword|dword|byte)_[0-9A-Fa-f]+);", stmt)
    if m:
        name = m.group(1)
        addr = int(name.split("_", 1)[1], 16)
        return {
            "kind": "return_global",
            "statement": stmt,
            "body_return": f"recovered_global_value(ctx, \"{name}\", 0x{addr:x}ULL)",
        }

    m = re.fullmatch(r"return\s+((?:off|qword|dword)_[0-9A-Fa-f]+)\((.*)\);", stmt)
    if m:
        name = m.group(1)
        addr = int(name.split("_", 1)[1], 16)
        return {
            "kind": "return_indirect_call",
            "statement": stmt,
            "body_return": f"recovered_indirect_call(ctx, \"{name}\", 0x{addr:x}ULL)",
        }

    m = re.fullmatch(r"return\s+(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
    if m:
        call = m.group(1)
        target_symbol = source_symbol_for_sub(call, addr_to_symbol)
        if target_symbol:
            return {
                "kind": "return_direct_call",
                "statement": stmt,
                "body_return": f"{target_symbol}(ctx)",
                "target_symbol": target_symbol,
            }
        target_addr = int(call.split("_", 1)[1], 16)
        return {
            "kind": "return_direct_call_unmapped",
            "statement": stmt,
            "body_return": f"recovered_direct_call(ctx, \"{call}\", 0x{target_addr:x}ULL)",
        }

    return None


def rewrite_function_body(text: str, symbol: str, addr: str, rewrite: dict[str, Any]) -> tuple[str, bool]:
    pattern = re.compile(
        rf"uintptr_t\s+{re.escape(symbol)}\(struct recovered_context \*ctx\)\s*\{{\n"
        rf"    /\* evidence: original IDA name .*? image offset {re.escape(addr)} \*/\n"
        rf"    recovered_mark_(?:lifted|semantic)\(ctx\);\n"
        rf"    recovered_trace\(ctx, \"{re.escape(symbol)}\", {re.escape(addr)}ULL\);\n"
        rf"    return 0;\n"
        rf"\}}",
        re.DOTALL,
    )
    body = (
        f"uintptr_t {symbol}(struct recovered_context *ctx)\n"
        "{\n"
        f"    /* semantic rewrite: {rewrite['statement']} */\n"
        f"    recovered_trace(ctx, \"{symbol}\", {addr}ULL);\n"
        f"    return {rewrite['body_return']};\n"
        "}"
    )
    new_text, count = pattern.subn(body, text, count=1)
    return new_text, count == 1


def update_quality_report(path: Path, function_map: list[dict[str, Any]]) -> None:
    report = read_json(path)
    counts = {"semantic-c": 0, "lifted-c": 0, "asm-fallback": 0}
    for fn in function_map:
        cls = fn.get("output_class")
        if cls in counts:
            counts[cls] += 1
    report["source_class_counts"] = counts
    report["generated_source_function_count"] = sum(counts.values())
    report["semantic_rewrite_policy"] = "simple evidence-backed rewrites may promote lifted-c to semantic-c only when wrapper bodies are replaced."
    write_json(path, report)


def apply_batch(case_id: str, source_file: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo_roots = [
        ROOT / "recovered-repos" / case_id / "recovered-hypervisor",
        s08 / "recovered-hypervisor",
    ]

    function_map_path = s08 / "function-map.json"
    function_map_doc = read_json(function_map_path)
    function_map = function_map_doc["functions"]
    addr_to_symbol = {normalize_addr(fn["address"]): fn["source_symbol"] for fn in function_map}
    decompile = {
        normalize_addr(fn["address"]): fn
        for fn in read_json(s07 / "decompile-export-full.json")["functions"]
    }

    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("semantic_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_simple_return(lines, addr_to_symbol)
        if not rewrite:
            skipped.append({"address": fn["address"], "source_symbol": fn["source_symbol"], "reason": "not_simple_safe_pattern"})
            continue
        selected.append({"function": fn, "rewrite": rewrite})
        if len(selected) >= max_functions:
            break

    applied: list[dict[str, Any]] = []
    for root in repo_roots:
        path = root / source_file
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for item in selected:
            fn = item["function"]
            rewrite = item["rewrite"]
            text, ok = rewrite_function_body(text, fn["source_symbol"], fn["address"], rewrite)
            if root == repo_roots[0]:
                applied.append(
                    {
                        "address": fn["address"],
                        "source_symbol": fn["source_symbol"],
                        "source_file": source_file,
                        "rewrite_kind": rewrite["kind"],
                        "statement": rewrite["statement"],
                        "applied": ok,
                        "target_symbol": rewrite.get("target_symbol"),
                    }
                )
        path.write_text(text, encoding="utf-8", newline="\n")

    applied_by_addr = {row["address"]: row for row in applied if row["applied"]}
    for fn in function_map:
        row = applied_by_addr.get(fn["address"])
        if not row:
            continue
        fn["output_class"] = "semantic-c"
        fn["confidence"] = "high" if row["rewrite_kind"] == "return_constant" else fn.get("confidence", "medium")
        fn["semantic_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/semantic-rewrite-index.jsonl")

    function_map_doc["semantic_rewrite_iteration"] = "S08-SEMANTIC-RW1"
    write_json(function_map_path, function_map_doc)
    update_quality_report(s08 / "source-quality-report.json", function_map)

    index_path = s08 / "semantic-rewrite-index.jsonl"
    prior: list[dict[str, Any]] = []
    if index_path.exists():
        prior = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = prior + [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-SEMANTIC-RW1",
            "generated_at": now_iso(),
        }
        for row in applied
    ]
    write_jsonl(index_path, rows)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-SEMANTIC-RW1",
        "source_file": source_file,
        "requested_max": max_functions,
        "selected": len(selected),
        "applied_this_batch": sum(1 for row in applied if row["applied"]),
        "applied_cumulative": sum(1 for row in rows if row.get("applied")),
        "skipped_before_limit": len(skipped),
        "rewrite_kinds": {},
        "boundary": "Only simple one-statement Hex-Rays return patterns were rewritten; complex functions remain lifted-c.",
    }
    for row in applied:
        if row["applied"]:
            summary["rewrite_kinds"][row["rewrite_kind"]] = summary["rewrite_kinds"].get(row["rewrite_kind"], 0) + 1
    write_json(s08 / "semantic-rewrite-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file", required=True)
    ap.add_argument("--max-functions", type=int, default=50)
    args = ap.parse_args()
    summary = apply_batch(args.case_id, args.source_file, args.max_functions)
    print(json.dumps(summary, ensure_ascii=False))


if __name__ == "__main__":
    main()
