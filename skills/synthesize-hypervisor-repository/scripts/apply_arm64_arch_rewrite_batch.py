#!/usr/bin/env python3
"""Apply conservative ARM64 architecture semantic rewrites.

This S08 helper targets small functions whose Hex-Rays body is made of ARM64
barriers/cache/TLB operations plus an optional direct call or JUMPOUT.
It intentionally skips functions with ordinary dataflow, loops, stores, or
complex expressions.
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


def addr_to_symbol_map(function_map: list[dict[str, Any]]) -> dict[str, str]:
    return {normalize_addr(fn["address"]): fn["source_symbol"] for fn in function_map}


def parse_number(text: str) -> str:
    value = text.rstrip("uU")
    if value.startswith("0x") or value.startswith("0X"):
        return f"{int(value, 16)}ULL"
    return f"{int(value, 10)}ULL"


def symbol_for_sub(name: str, addr_to_symbol: dict[str, str]) -> str | None:
    m = re.fullmatch(r"sub_([0-9A-Fa-f]+)", name)
    if not m:
        return None
    return addr_to_symbol.get(hex(int(m.group(1), 16)))


def classify_arch_body(lines: list[str], addr_to_symbol: dict[str, str]) -> dict[str, Any] | None:
    inner = [line.strip() for line in lines[2:-1] if line.strip()]
    if not inner or len(inner) > 8:
        return None

    actions: list[str] = []
    evidence: list[str] = []
    terminal_return = "0ULL"
    terminal_kind = "fallthrough"
    saw_arch = False

    for stmt in inner:
        m = re.fullmatch(r"__(dsb|isb|dmb)\((0x[0-9A-Fa-f]+|\d+)u?\);", stmt)
        if m:
            op = m.group(1).upper()
            domain = parse_number(m.group(2))
            actions.append(f"    recovered_arm64_barrier(ctx, \"{op}\", {domain});")
            evidence.append(stmt)
            saw_arch = True
            continue

        m = re.fullmatch(r"__asm\s*\{\s*(TLBI|IC|DC)\s+([A-Za-z0-9_]+)\s*\}", stmt)
        if m:
            group = m.group(1)
            op = m.group(2)
            if group == "TLBI":
                actions.append(f"    recovered_arm64_tlbi(ctx, \"{op}\");")
            else:
                actions.append(f"    recovered_arm64_cache_op(ctx, \"{group} {op}\");")
            evidence.append(stmt)
            saw_arch = True
            continue

        m = re.fullmatch(r"return\s+(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
        if m:
            call = m.group(1)
            target = symbol_for_sub(call, addr_to_symbol)
            if target:
                terminal_return = f"{target}(ctx)"
            else:
                target_addr = int(call.split("_", 1)[1], 16)
                terminal_return = f"recovered_direct_call(ctx, \"{call}\", 0x{target_addr:x}ULL)"
            terminal_kind = "return_direct_call"
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"JUMPOUT\(0x([0-9A-Fa-f]+)\);", stmt)
        if m:
            terminal_return = f"recovered_arm64_jumpout(ctx, 0x{int(m.group(1), 16):x}ULL)"
            terminal_kind = "jumpout"
            evidence.append(stmt)
            continue

        return None

    if not saw_arch:
        return None
    return {
        "kind": f"arm64_arch_{terminal_kind}",
        "evidence_statements": evidence,
        "actions": actions,
        "terminal_return": terminal_return,
    }


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
    evidence = "; ".join(rewrite["evidence_statements"])
    actions = "\n".join(rewrite["actions"])
    body = (
        f"uintptr_t {symbol}(struct recovered_context *ctx)\n"
        "{\n"
        f"    /* arm64 semantic rewrite: {evidence} */\n"
        f"    recovered_trace(ctx, \"{symbol}\", {addr}ULL);\n"
        f"{actions}\n"
        f"    return {rewrite['terminal_return']};\n"
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
    report["arm64_arch_rewrite_policy"] = "small barrier/cache/TLB helpers may promote to semantic-c only when generic wrapper bodies are replaced."
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
    addr_to_symbol = addr_to_symbol_map(function_map)
    decompile = {
        normalize_addr(fn["address"]): fn
        for fn in read_json(s07 / "decompile-export-full.json")["functions"]
    }

    selected: list[dict[str, Any]] = []
    skipped = 0
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("semantic_rewrite") == "applied" or fn.get("arm64_arch_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_arch_body(lines, addr_to_symbol)
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
                        "statements": rewrite["evidence_statements"],
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
        fn["confidence"] = "high"
        fn["arm64_arch_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/arm64-arch-rewrite-index.jsonl")

    function_map_doc["arm64_arch_rewrite_iteration"] = "S08-ARM64-ARCH-RW1"
    write_json(function_map_path, function_map_doc)
    update_quality_report(s08 / "source-quality-report.json", function_map)

    index_path = s08 / "arm64-arch-rewrite-index.jsonl"
    prior: list[dict[str, Any]] = []
    if index_path.exists():
        prior = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = prior + [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-ARM64-ARCH-RW1",
            "generated_at": now_iso(),
        }
        for row in applied
    ]
    write_jsonl(index_path, rows)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-ARM64-ARCH-RW1",
        "source_file": source_file,
        "requested_max": max_functions,
        "selected": len(selected),
        "applied_this_batch": sum(1 for row in applied if row["applied"]),
        "applied_cumulative": sum(1 for row in rows if row.get("applied")),
        "skipped_before_limit": skipped,
        "rewrite_kinds": {},
        "boundary": "Only small ARM64 barrier/cache/TLB helpers were rewritten; complex dataflow remains lifted-c.",
    }
    for row in applied:
        if row["applied"]:
            summary["rewrite_kinds"][row["rewrite_kind"]] = summary["rewrite_kinds"].get(row["rewrite_kind"], 0) + 1
    write_json(s08 / "arm64-arch-rewrite-summary.json", summary)
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
