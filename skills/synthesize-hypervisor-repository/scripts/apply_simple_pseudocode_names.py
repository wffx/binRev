#!/usr/bin/env python3
"""Apply conservative names for mechanically simple pseudocode functions.

This pass is intentionally strict.  It renames only generic source symbols
whose S07 pseudocode body reduces to one of a few unambiguous shapes:

- pure `return CONSTANT;`
- pure `return sub_xxx(...);`
- pure `sub_xxx(...);`

It does not use Oracle data, does not infer high-level subsystem semantics, and
does not promote output_class.  The goal is to reduce obviously unhelpful
`runtime_helper_NNNN` names where the decompiler evidence supports a stable
role such as `runtime_return_error_code_01` or `runtime_forward_call_01`.
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
GENERIC_RE = re.compile(
    r"^(?:(?:runtime_helper|boot_helper|cache_helper|mmu_helper|mmu_switch_or_enable|percpu_access|timer_event|timer_control|interrupt_helper|interrupt_route|exception_helper|stage2_helper|unknown_helper)_\d{4}|(?:runtime_access_current_cpu_state|percpu_access_current_cpu_state|boot_access_current_cpu_state|arm64_cache_tlb_maintenance)(?:_\d+)?)$"
)


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


def load_decompile(path: Path) -> dict[str, str]:
    doc = read_json(path)
    out: dict[str, str] = {}
    for fn in doc.get("functions", []):
        lines = fn.get("pseudocode", {}).get("lines", [])
        out[fn["address"].lower()] = "\n".join(lines)
    return out


def executable_statements(pseudocode: str) -> list[str]:
    if "{" not in pseudocode or "}" not in pseudocode:
        return []
    body = pseudocode[pseudocode.find("{") + 1 : pseudocode.rfind("}")]
    out: list[str] = []
    decl_re = re.compile(
        r"^(?:__int64|int|unsigned|signed|_QWORD|_DWORD|BOOL|bool|char|void|_BOOL8|unsigned\s+__int64|unsigned\s+int|signed\s+__int64)\b.*;$"
    )
    for line in body.splitlines():
        stmt = line.strip()
        if not stmt or stmt.startswith("//"):
            continue
        if "//" in stmt:
            stmt = stmt.split("//", 1)[0].strip()
        if not stmt:
            continue
        if decl_re.match(stmt):
            continue
        out.append(stmt)
    return out


def module_prefix(module: str, source_file: str) -> str:
    if module in {"runtime", "cache", "percpu", "boot", "exception", "interrupt", "timer", "mmu"}:
        return module
    if source_file:
        stem = Path(source_file).stem
        if stem:
            return stem
    return "recovered"


def classify(fn: dict[str, Any], pseudocode: str) -> tuple[str, str, dict[str, Any]] | None:
    statements = executable_statements(pseudocode)
    if len(statements) != 1:
        return None
    stmt = statements[0]
    prefix = module_prefix(str(fn.get("module", "")), str(fn.get("source_file", "")))

    m = re.fullmatch(r"return\s+(?P<const>(?:0x[0-9A-Fa-f]+|\d+)(?:LL|ULL|L)?)\s*;", stmt)
    if m:
        value = m.group("const")
        base = f"{prefix}_return_zero" if value in {"0", "0LL", "0ULL", "0L"} else f"{prefix}_return_constant"
        if value.startswith("4294967") or value.lower().startswith("0xffff"):
            base = f"{prefix}_return_error_code"
        return base, "single-statement constant return", {"statement": stmt, "constant": value}

    m = re.fullmatch(r"return\s+(?P<callee>sub_[0-9A-Fa-f]+)\s*\(.*\)\s*;", stmt)
    if m:
        return f"{prefix}_forward_call", "single-statement direct tail call", {"statement": stmt, "callee": m.group("callee")}

    m = re.fullmatch(r"(?P<callee>sub_[0-9A-Fa-f]+)\s*\(.*\)\s*;", stmt)
    if m:
        return f"{prefix}_invoke_call", "single-statement direct call", {"statement": stmt, "callee": m.group("callee")}

    return None


def unique_name(base: str, used: set[str], counters: dict[str, int]) -> str:
    if base not in used:
        used.add(base)
        return base
    counters[base] += 1
    while True:
        candidate = f"{base}_{counters[base]:02d}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        counters[base] += 1


def replace_symbols(repo: Path, renames: dict[str, str]) -> dict[str, int]:
    counts = {old: 0 for old in renames}
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.suffix not in {".c", ".h", ".S"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for old, new in sorted(renames.items(), key=lambda item: len(item[0]), reverse=True):
            text, n = re.subn(rf"\b{re.escape(old)}\b", new, text)
            counts[old] += n
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
    return counts


def apply(case_id: str, max_renames: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    fmap_path = s08 / "function-map.json"
    smap_path = s08 / "source-map.json"
    fmap = read_json(fmap_path)
    smap = read_json(smap_path)
    functions = fmap.get("functions", [])
    decompile = load_decompile(s07 / "decompile-export-full.json")
    used = {fn.get("source_symbol", "") for fn in functions}
    counters: dict[str, int] = defaultdict(int)

    plan: list[dict[str, Any]] = []
    for fn in functions:
        old = fn.get("source_symbol", "")
        if not GENERIC_RE.fullmatch(old):
            continue
        classified = classify(fn, decompile.get(fn["address"].lower(), ""))
        if not classified:
            continue
        base, reason, evidence = classified
        new = unique_name(base, used, counters)
        plan.append(
            {
                "address": fn["address"],
                "old_symbol": old,
                "new_symbol": new,
                "source_file": fn.get("source_file"),
                "module": fn.get("module"),
                "output_class": fn.get("output_class"),
                "reason": reason,
                "evidence": evidence,
                "boundary": "Simple pseudocode name only; output_class and body are unchanged.",
            }
        )
        if len(plan) >= max_renames:
            break

    renames = {row["old_symbol"]: row["new_symbol"] for row in plan}
    counts = replace_symbols(repo, renames)
    by_addr = {fn["address"].lower(): fn for fn in functions}
    for row in plan:
        fn = by_addr[row["address"].lower()]
        fn["source_symbol"] = row["new_symbol"]
        fn["semantic_name"] = row["new_symbol"]
        fn.setdefault("evidence", []).append("S08/simple-pseudocode-name-index.jsonl")
        row["occurrences_replaced"] = counts.get(row["old_symbol"], 0)

    for entry in smap.get("function_sources", []):
        symbol = entry.get("symbol") or entry.get("source_symbol")
        if symbol in renames:
            if "symbol" in entry:
                entry["symbol"] = renames[symbol]
            if "source_symbol" in entry:
                entry["source_symbol"] = renames[symbol]
            entry["semantic_name"] = renames[symbol]

    previous = read_jsonl(s08 / "simple-pseudocode-name-index.jsonl")
    iteration_id = f"S08-SIMPLE-PSEUDOCODE-NAME-RW{len({r.get('iteration_id') for r in previous}) + 1}"
    rows = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": iteration_id,
            "generated_at": now_iso(),
        }
        for row in plan
    ]
    fmap["simple_pseudocode_name_iteration"] = iteration_id
    smap["simple_pseudocode_name_iteration"] = iteration_id
    write_json(fmap_path, fmap)
    write_json(smap_path, smap)
    write_jsonl(s08 / "simple-pseudocode-name-index.jsonl", previous + rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "requested_max": max_renames,
        "renamed_this_run": len(rows),
        "total_rows": len(previous) + len(rows),
        "occurrences_replaced_this_run": sum(row.get("occurrences_replaced", 0) for row in rows),
        "boundary": "Only mechanically simple pseudocode functions were renamed; no semantic promotion.",
    }
    write_json(s08 / "simple-pseudocode-name-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-renames", type=int, default=100)
    args = ap.parse_args()
    print(json.dumps(apply(args.case_id, args.max_renames), ensure_ascii=False))


if __name__ == "__main__":
    main()
