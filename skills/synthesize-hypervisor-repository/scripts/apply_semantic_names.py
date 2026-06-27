#!/usr/bin/env python3
"""Apply evidence-backed semantic source names.

This S08 helper renames source symbols only when a previous semantic rewrite
index provides a concrete behavioral class. Address/IDA names remain in
evidence maps, not as primary source symbols.
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
    r"^(?:runtime_helper|boot_helper|cache_helper|mmu_helper|mmu_switch_or_enable|percpu_access|timer_event|timer_control|interrupt_helper|interrupt_route|exception_helper|stage2_helper|unknown_helper)_\d{4}$"
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
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def load_index(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def base_name(row: dict[str, Any]) -> str | None:
    kind = row.get("rewrite_kind", "")
    if kind == "diagnostic_summary":
        return {
            "runtime_request_machine_reboot_01": "runtime_request_delayed_reboot",
            "runtime_helper_0015": "scheduler_initialize_credit_state",
            "runtime_helper_0017": "runtime_vprintk_frontend",
            "runtime_helper_0025": "interrupt_report_unexpected_target",
            "runtime_helper_0027": "runtime_handle_division_by_zero",
            "runtime_helper_0049": "dt_validate_pci_compatible_device",
        }.get(row.get("source_symbol", ""))
    source_file = row.get("source_file", "")
    if source_file.endswith("boot.c"):
        return {
            "boot_currentel_guard": "boot_require_el2_or_wait",
            "boot_secondary_wait": "boot_wait_for_secondary_cpu_release",
            "boot_elr_handoff": "boot_resume_from_elr",
            "boot_daif_call_chain": "boot_run_with_interrupts_masked",
        }.get(kind)
    if source_file.endswith("cache.c"):
        return {
            "arm64_arch_return_direct_call": "arm64_barrier_then_call",
            "arm64_arch_jumpout": "arm64_barrier_then_jumpout",
            "arm64_arch_fallthrough": "arm64_tlbi_local_flush",
        }.get(kind)
    if source_file.endswith("percpu.c"):
        return {
            "percpu_base_read": "percpu_current_context",
            "percpu_callsite": "percpu_dispatch_current_context_call",
            "percpu_tpidr_expression": "percpu_read_current_cpu_expression",
        }.get(kind)
    if source_file.endswith("runtime.c"):
        return {
            "return_constant": "runtime_return_constant",
            "return_global": "runtime_return_global_value",
            "return_indirect_call": "runtime_call_indirect_entry",
            "return_direct_call": "runtime_forward_call",
            "return_direct_call_unmapped": "runtime_forward_unmapped_call",
        }.get(kind)
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
    counts: dict[str, int] = {old: 0 for old in renames}
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


def repair_evidence_comments(repo: Path, functions: list[dict[str, Any]]) -> None:
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in functions:
        by_file[fn["source_file"]].append(fn)
    for rel, rows in by_file.items():
        path = repo / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for fn in rows:
            addr = re.escape(fn["address"].lower())
            ida_name = fn["ida_name"]
            text = re.sub(
                rf"(/\* evidence: image offset {addr}, IDA )[^,]+(, range )",
                rf"\g<1>{ida_name}\g<2>",
                text,
                flags=re.IGNORECASE,
            )
            text = re.sub(
                rf"(/\* evidence: original IDA name )[^,]+(, image offset {addr} \*/)",
                rf"\g<1>{ida_name}\g<2>",
                text,
                flags=re.IGNORECASE,
            )
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")


def apply_names(case_id: str, max_renames: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    function_map_path = s08 / "function-map.json"
    source_map_path = s08 / "source-map.json"
    function_map_doc = read_json(function_map_path)
    source_map_doc = read_json(source_map_path)
    functions = function_map_doc["functions"]
    by_addr = {fn["address"]: fn for fn in functions}

    rows: list[dict[str, Any]] = []
    for name in [
        "semantic-rewrite-index.jsonl",
        "arm64-arch-rewrite-index.jsonl",
        "percpu-rewrite-index.jsonl",
        "boot-rewrite-index.jsonl",
        "diagnostic-summary-rewrite-index.jsonl",
    ]:
        rows.extend(load_index(s08 / name))
    previous_name_rows = load_index(s08 / "semantic-name-index.jsonl")

    used = {fn["source_symbol"] for fn in functions}
    counters: dict[str, int] = defaultdict(int)
    plan: list[dict[str, Any]] = []
    for row in rows:
        if not row.get("applied"):
            continue
        fn = by_addr.get(row["address"])
        if not fn:
            continue
        old = fn["source_symbol"]
        base = base_name(row)
        if not base:
            continue
        if not GENERIC_RE.fullmatch(old) and old not in {
            "runtime_request_machine_reboot_01",
        }:
            continue
        new = unique_name(base, used, counters)
        plan.append(
            {
                "address": row["address"],
                "old_symbol": old,
                "new_symbol": new,
                "source_file": fn["source_file"],
                "rewrite_kind": row.get("rewrite_kind"),
                "evidence": row.get("iteration_id"),
            }
        )
        if len(plan) >= max_renames:
            break

    renames = {row["old_symbol"]: row["new_symbol"] for row in plan}
    occurrence_counts = replace_symbols(repo, renames)

    for row in plan:
        fn = by_addr[row["address"]]
        fn["source_symbol"] = row["new_symbol"]
        fn["semantic_name"] = row["new_symbol"]
        fn.setdefault("evidence", []).append("S08/semantic-name-index.jsonl")
        row["occurrences_replaced"] = occurrence_counts.get(row["old_symbol"], 0)

    for entry in source_map_doc.get("function_sources", []):
        symbol = entry.get("source_symbol") or entry.get("symbol")
        if symbol in renames:
            if "source_symbol" in entry:
                entry["source_symbol"] = renames[symbol]
            if "symbol" in entry:
                entry["symbol"] = renames[symbol]
            entry["semantic_name"] = renames[symbol]

    repair_evidence_comments(repo, functions)

    function_map_doc["semantic_name_iteration"] = "S08-SEMANTIC-NAME-RW1"
    source_map_doc["semantic_name_iteration"] = "S08-SEMANTIC-NAME-RW1"
    write_json(function_map_path, function_map_doc)
    write_json(source_map_path, source_map_doc)
    iteration_id = f"S08-SEMANTIC-NAME-RW{len({row.get('iteration_id') for row in previous_name_rows if row.get('iteration_id')}) + 1}"
    write_jsonl(
        s08 / "semantic-name-index.jsonl",
        previous_name_rows
        + [
            {
                **row,
                "case_id": case_id,
                "stage_id": "S08",
                "iteration_id": iteration_id,
                "generated_at": now_iso(),
            }
            for row in plan
        ],
    )
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "requested_max": max_renames,
        "renamed": len(plan),
        "renamed_cumulative": len(previous_name_rows) + len(plan),
        "total_occurrences_replaced": sum(row.get("occurrences_replaced", 0) for row in plan),
        "boundary": "Only functions with applied semantic rewrite evidence were renamed. IDA/address names remain in evidence maps.",
    }
    write_json(s08 / "semantic-name-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-renames", type=int, default=200)
    args = ap.parse_args()
    print(json.dumps(apply_names(args.case_id, args.max_renames), ensure_ascii=False))


if __name__ == "__main__":
    main()
