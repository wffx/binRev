#!/usr/bin/env python3
"""Apply conservative log/diagnostic sequence rewrites.

This S08 helper targets short straight-line functions dominated by diagnostic
print calls such as sub_1C18(...). It preserves original call expressions as
summaries and skips branches, loops, switches, stores, and unclear dataflow.
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
LOG_CALLS = {"sub_1C18"}


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


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def c_comment(value: str) -> str:
    return value.replace("*/", "* /").replace("\r", "\\r").replace("\n", "\\n")


def is_decl(line: str) -> bool:
    return "//" in line and bool(
        re.match(
            r"^(?:unsigned\s+|signed\s+)?(?:__int64|int|char|bool|void|unsigned int|signed int|unsigned __int64|_DWORD|_QWORD)(?:\s+\*+|\s+)[A-Za-z_][A-Za-z0-9_]*;",
            line,
        )
    )


def extract_body_lines(lines: list[str]) -> list[str]:
    body = [line.strip() for line in lines[2:-1] if line.strip()]
    return [line for line in body if not is_decl(line) and line not in {"{", "}"}]


def split_statements(lines: list[str]) -> list[str] | None:
    stmts: list[str] = []
    current: list[str] = []
    balance = 0
    for line in lines:
        if re.match(r"^(if|else|for|while|switch|case|default|do|break|continue)\b", line):
            return None
        if line in {"{", "}"}:
            return None
        current.append(line)
        balance += line.count("(") - line.count(")")
        if line.endswith(";") and balance <= 0:
            stmt = " ".join(current)
            stmt = re.sub(r"\s+", " ", stmt).strip()
            stmts.append(stmt)
            current = []
            balance = 0
    if current:
        return None
    return stmts


def sub_addr(call: str) -> int | None:
    m = re.fullmatch(r"sub_([0-9A-Fa-f]+)", call)
    if not m:
        return None
    return int(m.group(1), 16)


def classify_log_sequence(lines: list[str]) -> dict[str, Any] | None:
    stmts = split_statements(extract_body_lines(lines))
    if not stmts or len(stmts) > 12:
        return None

    actions: list[str] = []
    evidence: list[str] = []
    terminal_return = "0ULL"
    saw_log = False

    for stmt in stmts:
        m = re.fullmatch(r"(?:(?:[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
        if m:
            call, args = m.group(1), m.group(2).strip()
            addr = sub_addr(call)
            summary = f"{call}({args})"
            if call in LOG_CALLS:
                actions.append(f"    recovered_log(ctx, {c_string(summary)});")
                saw_log = True
            elif addr is not None:
                actions.append(f"    (void)recovered_direct_call(ctx, {c_string(summary)}, 0x{addr:x}ULL);")
            else:
                return None
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"return\s+(sub_[0-9A-Fa-f]+)\((.*)\);", stmt)
        if m:
            call, args = m.group(1), m.group(2).strip()
            addr = sub_addr(call)
            if addr is None:
                return None
            if call in LOG_CALLS:
                actions.append(f"    recovered_log(ctx, {c_string(f'{call}({args})')});")
                saw_log = True
            terminal_return = f"recovered_direct_call(ctx, {c_string(f'{call}({args})')}, 0x{addr:x}ULL)"
            evidence.append(stmt)
            continue

        m = re.fullmatch(r"return\s+(0x[0-9A-Fa-f]+|-?\d+);", stmt)
        if m:
            value = m.group(1)
            if value.startswith("-"):
                terminal_return = f"(uintptr_t)(intptr_t){value}"
            elif value.startswith("0x"):
                terminal_return = f"{value}ULL"
            else:
                terminal_return = f"{value}ULL"
            evidence.append(stmt)
            continue

        return None

    if not saw_log:
        return None
    return {
        "kind": "log_sequence",
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
    evidence = c_comment("; ".join(rewrite["evidence_statements"]))
    actions = "\n".join(rewrite["actions"])
    body = (
        f"uintptr_t {symbol}(struct recovered_context *ctx)\n"
        "{\n"
        f"    /* log-sequence semantic rewrite: {evidence} */\n"
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
    report["log_sequence_rewrite_policy"] = "short straight-line diagnostic/logging sequences may promote to semantic-c only when wrapper bodies are replaced."
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
    decompile = {normalize_addr(fn["address"]): fn for fn in read_json(s07 / "decompile-export-full.json")["functions"]}

    selected: list[dict[str, Any]] = []
    skipped = 0
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("log_sequence_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_log_sequence(lines)
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
        fn["log_sequence_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/log-sequence-rewrite-index.jsonl")

    function_map_doc["log_sequence_rewrite_iteration"] = "S08-LOG-SEQUENCE-RW1"
    write_json(function_map_path, function_map_doc)

    source_map_path = s08 / "source-map.json"
    source_map_doc = read_json(source_map_path)
    for entry in source_map_doc.get("function_sources", []):
        if entry.get("function") in applied_by_addr:
            entry["output_class"] = "semantic-c"
    source_map_doc["log_sequence_rewrite_iteration"] = "S08-LOG-SEQUENCE-RW1"
    write_json(source_map_path, source_map_doc)
    update_quality_report(s08 / "source-quality-report.json", function_map)

    index_path = s08 / "log-sequence-rewrite-index.jsonl"
    prior = read_jsonl(index_path)
    iteration_id = f"S08-LOG-SEQUENCE-RW{len({row.get('iteration_id') for row in prior if row.get('iteration_id')}) + 1}"
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
        "boundary": "Only short straight-line diagnostic/logging sequences were rewritten; control/data flow remains lifted-c.",
    }
    write_json(s08 / "log-sequence-rewrite-summary.json", summary)
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
