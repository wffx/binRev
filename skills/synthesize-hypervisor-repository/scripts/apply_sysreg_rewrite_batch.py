#!/usr/bin/env python3
"""Apply conservative ARM64 system-register semantic rewrites.

This S08 helper targets short functions whose Hex-Rays body is made of
_ReadStatusReg/_WriteStatusReg operations, ISB/DSB/DMB barriers, and optional
direct calls. It is intended for EL2/GIC/timer helpers and deliberately skips
ordinary control flow, loops, switches, stores, and unclear dataflow.
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


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def normalize_addr(addr: str) -> str:
    return hex(int(addr, 16))


def symbol_for_sub(name: str, addr_to_symbol: dict[str, str]) -> str | None:
    m = re.fullmatch(r"sub_([0-9A-Fa-f]+)", name)
    if not m:
        return None
    return addr_to_symbol.get(hex(int(m.group(1), 16)))


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def parse_barrier(stmt: str) -> str | None:
    m = re.fullmatch(r"__(isb|dsb|dmb)\((0x[0-9A-Fa-f]+|\d+)u?\);", stmt)
    if not m:
        return None
    op = m.group(1).upper()
    domain = m.group(2).rstrip("uU")
    value = int(domain, 16) if domain.lower().startswith("0x") else int(domain)
    return f"    recovered_arm64_barrier(ctx, {c_string(op)}, {value}ULL);"


def strip_unsigned_suffix(expr: str) -> str:
    return re.sub(r"(?<=\d)uLL\b|(?<=\d)ULL\b|(?<=\d)u\b|(?<=\d)U\b", "ULL", expr)


def replace_read_expr(expr: str) -> str:
    def repl(match: re.Match[str]) -> str:
        return f"recovered_arm64_sysreg_read(ctx, {c_string(match.group(1))})"

    expr = re.sub(r"_ReadStatusReg\(([A-Za-z0-9_]+)\)", repl, expr)
    expr = re.sub(r"\(unsigned int\)\s*(recovered_arm64_sysreg_read\([^)]+\))", r"\1", expr)
    expr = strip_unsigned_suffix(expr)
    return expr


def is_decl(stmt: str) -> bool:
    if "//" not in stmt:
        return False
    return bool(
        re.match(
            r"^(?:unsigned\s+)?(?:__int64|int|char|bool|signed int|unsigned int|unsigned __int64|_DWORD|_QWORD|uintptr_t)(?:\s+\*+|\s+)[A-Za-z_][A-Za-z0-9_]*;",
            stmt,
        )
    )


def inner_statements(lines: list[str]) -> list[str]:
    body = [line.strip() for line in lines[2:-1] if line.strip()]
    out: list[str] = []
    for stmt in body:
        if stmt in {"{", "}"}:
            continue
        if is_decl(stmt):
            continue
        out.append(stmt)
    return out


def classify_sysreg_body(lines: list[str], addr_to_symbol: dict[str, str]) -> dict[str, Any] | None:
    stmts = inner_statements(lines)
    if not stmts or len(stmts) > 8:
        return None

    actions: list[str] = []
    evidence: list[str] = []
    read_vars: dict[str, str] = {}
    terminal_return = "0ULL"
    saw_sysreg = False

    for stmt in stmts:
        barrier = parse_barrier(stmt)
        if barrier:
            actions.append(barrier)
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*_ReadStatusReg\(([A-Za-z0-9_]+)\);", stmt)
        if m:
            var, reg = m.group(1), m.group(2)
            read_vars[var] = f"{var}_value"
            actions.append(f"    uintptr_t {var}_value = recovered_arm64_sysreg_read(ctx, {c_string(reg)});")
            evidence.append(stmt)
            saw_sysreg = True
            continue

        m = re.fullmatch(r"_WriteStatusReg\(([A-Za-z0-9_]+),\s*(.*)\);", stmt)
        if m:
            reg, value = m.group(1), m.group(2)
            actions.append(f"    recovered_arm64_sysreg_write(ctx, {c_string(reg)}, {c_string(value)});")
            evidence.append(stmt)
            saw_sysreg = True
            continue

        m = re.fullmatch(r"(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
        if m:
            call = m.group(1)
            args = m.group(2).strip()
            target = symbol_for_sub(call, addr_to_symbol)
            if target and not args:
                actions.append(f"    (void){target}(ctx);")
            else:
                target_addr = int(call.split("_", 1)[1], 16)
                summary = call if not args else f"{call}({args})"
                actions.append(f"    (void)recovered_direct_call(ctx, {c_string(summary)}, 0x{target_addr:x}ULL);")
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"return\s+(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
        if m:
            call = m.group(1)
            args = m.group(2).strip()
            target = symbol_for_sub(call, addr_to_symbol)
            if target and not args:
                terminal_return = f"{target}(ctx)"
            else:
                target_addr = int(call.split("_", 1)[1], 16)
                summary = call if not args else f"{call}({args})"
                terminal_return = f"recovered_direct_call(ctx, {c_string(summary)}, 0x{target_addr:x}ULL)"
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"return\s+(.*);", stmt)
        if m:
            original_expr = m.group(1)
            expr = replace_read_expr(original_expr)
            for old, new in read_vars.items():
                expr = re.sub(rf"\b{re.escape(old)}\b", new, expr)
            if "_ReadStatusReg" in expr:
                return None
            if "_ReadStatusReg" in original_expr:
                saw_sysreg = True
            terminal_return = expr
            evidence.append(stmt)
            continue

        return None

    if not saw_sysreg:
        return None
    return {
        "kind": "arm64_sysreg_sequence",
        "actions": actions,
        "terminal_return": terminal_return,
        "evidence_statements": evidence,
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
        f"    /* sysreg semantic rewrite: {evidence} */\n"
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
    report["sysreg_rewrite_policy"] = "short ARM64 system-register read/write helpers may promote to semantic-c only when wrapper bodies are replaced."
    write_json(path, report)


def apply_batch(case_id: str, source_file: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo_roots = [ROOT / "recovered-repos" / case_id / "recovered-hypervisor"]
    staged = s08 / "recovered-hypervisor"
    if staged.exists():
        repo_roots.append(staged)

    function_map_path = s08 / "function-map.json"
    function_map_doc = read_json(function_map_path)
    function_map = function_map_doc["functions"]
    addr_to_symbol = {normalize_addr(fn["address"]): fn["source_symbol"] for fn in function_map}
    decompile = {normalize_addr(fn["address"]): fn for fn in read_json(s07 / "decompile-export-full.json")["functions"]}

    selected: list[dict[str, Any]] = []
    skipped = 0
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("sysreg_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_sysreg_body(lines, addr_to_symbol)
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
        fn["sysreg_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/sysreg-rewrite-index.jsonl")

    for entry in read_json(s08 / "source-map.json").get("function_sources", []):
        if entry.get("function") in applied_by_addr:
            entry["output_class"] = "semantic-c"

    function_map_doc["sysreg_rewrite_iteration"] = "S08-SYSREG-RW1"
    write_json(function_map_path, function_map_doc)

    source_map_path = s08 / "source-map.json"
    source_map_doc = read_json(source_map_path)
    for entry in source_map_doc.get("function_sources", []):
        if entry.get("function") in applied_by_addr:
            entry["output_class"] = "semantic-c"
    source_map_doc["sysreg_rewrite_iteration"] = "S08-SYSREG-RW1"
    write_json(source_map_path, source_map_doc)
    update_quality_report(s08 / "source-quality-report.json", function_map)

    index_path = s08 / "sysreg-rewrite-index.jsonl"
    prior = read_jsonl(index_path)
    iteration_id = f"S08-SYSREG-RW{len({row.get('iteration_id') for row in prior if row.get('iteration_id')}) + 1}"
    new_rows = [
        {**row, "case_id": case_id, "stage_id": "S08", "iteration_id": iteration_id, "generated_at": now_iso()}
        for row in applied
    ]
    write_jsonl(index_path, prior + new_rows)

    kinds: dict[str, int] = defaultdict(int)
    for row in applied:
        if row["applied"]:
            kinds[row["rewrite_kind"]] += 1
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "source_file": source_file,
        "requested_max": max_functions,
        "selected": len(selected),
        "applied_this_batch": sum(1 for row in applied if row["applied"]),
        "applied_cumulative": sum(1 for row in prior + new_rows if row.get("applied")),
        "skipped_before_limit": skipped,
        "rewrite_kinds": dict(kinds),
        "boundary": "Only short ARM64 system-register helper sequences were rewritten; complex control/data flow remains lifted-c.",
    }
    write_json(s08 / "sysreg-rewrite-summary.json", summary)
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
