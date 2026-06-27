#!/usr/bin/env python3
"""Apply conservative per-CPU semantic rewrites.

This S08 helper fixes semantic-label/body mismatch in per-CPU modules. It only
rewrites one-statement returns that explicitly reference TPIDR_EL2. Complex
per-CPU state machines, locks, stores, and multi-branch functions remain as-is.
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


def c_string(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def classify_percpu_return(lines: list[str]) -> dict[str, Any] | None:
    inner = [line.strip() for line in lines[2:-1] if line.strip()]
    if len(inner) != 1:
        return None
    stmt = inner[0]
    if "_ReadStatusReg(TPIDR_EL2)" not in stmt:
        return None

    m = re.fullmatch(
        r"return\s+\*\(__int64 \*\)\(\(char \*\)&(qword_[0-9A-Fa-f]+)\s+\+\s+_ReadStatusReg\(TPIDR_EL2\)\);",
        stmt,
    )
    if m:
        base = m.group(1)
        base_addr = int(base.split("_", 1)[1], 16)
        return {
            "kind": "percpu_base_read",
            "statement": stmt,
            "body_return": f"recovered_percpu_read(ctx, \"{base}\", 0x{base_addr:x}ULL)",
        }

    m = re.fullmatch(r"return\s+(sub_[0-9A-Fa-f]+)\(.*_ReadStatusReg\(TPIDR_EL2\).*\);", stmt)
    if m:
        callee = m.group(1)
        callee_addr = int(callee.split("_", 1)[1], 16)
        return {
            "kind": "percpu_callsite",
            "statement": stmt,
            "body_return": f"recovered_percpu_callsite(ctx, \"{callee}\", 0x{callee_addr:x}ULL, \"TPIDR_EL2 per-cpu callsite\")",
        }

    if stmt.startswith("return "):
        return {
            "kind": "percpu_tpidr_expression",
            "statement": stmt,
            "body_return": "recovered_percpu_expr(ctx, \"TPIDR_EL2 per-cpu expression\", 0ULL)",
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
        f"    /* per-cpu semantic rewrite: {rewrite['kind']} */\n"
        f"    recovered_trace(ctx, \"{symbol}\", {addr}ULL);\n"
        f"    return {rewrite['body_return']};\n"
        "}"
    )
    new_text, count = pattern.subn(body, text, count=1)
    return new_text, count == 1


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
    decompile = {
        normalize_addr(fn["address"]): fn
        for fn in read_json(s07 / "decompile-export-full.json")["functions"]
    }

    selected: list[dict[str, Any]] = []
    skipped = 0
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("percpu_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_percpu_return(lines)
        if not rewrite:
            skipped += 1
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
                    }
                )
        path.write_text(text, encoding="utf-8", newline="\n")

    applied_by_addr = {row["address"]: row for row in applied if row["applied"]}
    for fn in function_map:
        row = applied_by_addr.get(fn["address"])
        if not row:
            continue
        fn["output_class"] = "semantic-c"
        fn["confidence"] = "high" if row["rewrite_kind"] == "percpu_base_read" else fn.get("confidence", "medium")
        fn["percpu_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/percpu-rewrite-index.jsonl")

    function_map_doc["percpu_rewrite_iteration"] = "S08-PERCPU-RW1"
    write_json(function_map_path, function_map_doc)

    index_path = s08 / "percpu-rewrite-index.jsonl"
    prior: list[dict[str, Any]] = []
    if index_path.exists():
        prior = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = prior + [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-PERCPU-RW1",
            "generated_at": now_iso(),
        }
        for row in applied
    ]
    write_jsonl(index_path, rows)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-PERCPU-RW1",
        "source_file": source_file,
        "requested_max": max_functions,
        "selected": len(selected),
        "applied_this_batch": sum(1 for row in applied if row["applied"]),
        "applied_cumulative": sum(1 for row in rows if row.get("applied")),
        "skipped_before_limit": skipped,
        "rewrite_kinds": {},
        "boundary": "Only one-statement TPIDR_EL2 per-CPU returns were rewritten; complex per-CPU state remains lifted/review-only.",
    }
    for row in applied:
        if row["applied"]:
            summary["rewrite_kinds"][row["rewrite_kind"]] = summary["rewrite_kinds"].get(row["rewrite_kind"], 0) + 1
    write_json(s08 / "percpu-rewrite-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file", required=True)
    ap.add_argument("--max-functions", type=int, default=50)
    args = ap.parse_args()
    print(json.dumps(apply_batch(args.case_id, args.source_file, args.max_functions), ensure_ascii=False))


if __name__ == "__main__":
    main()
