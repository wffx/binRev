#!/usr/bin/env python3
"""Apply names from reviewed S08 candidate indexes without promoting class.

This pass is intentionally narrow.  It consumes planning candidates such as
diagnostic-summary-candidates.jsonl and renames only functions whose evidence
terms identify a stable responsibility while the body remains lifted-c.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
GENERIC_RE = re.compile(
    r"^(?:runtime_helper|boot_helper|cache_helper|mmu_helper|stage2_helper|interrupt_helper|timer_control|timer_event|exception_helper|unknown_helper)_\d{4}$"
)


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
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def classify_candidate(row: dict[str, Any]) -> tuple[str, str] | None:
    addr = str(row.get("address", "")).lower()
    terms = " ".join(str(t) for t in row.get("evidence_terms", []))
    classes = set(row.get("behavior_classes", []))

    # Address-specific choices here are still evidence-backed: the candidate
    # index records exact pseudocode/string terms.  Keep this list narrow.
    if addr == "0x2178" and all(t in terms for t in ["aPc016lx", "aLr016lx", "aCpsr016lxModeS"]):
        return "runtime_dump_cpu_register_state", "register dump format strings"
    if addr == "0x4290" and "device_tree" in classes and "aRanges_0" in terms:
        return "dt_parse_child_address_ranges", "device-tree ranges parser strings"
    if addr == "0x5fd0" and "device_tree" in classes and "aRanges_0" in terms:
        return "dt_translate_address_ranges", "device-tree ranges translation strings"
    if addr == "0x4a80" and "aSCouldNotGetSF" in terms:
        return "dt_read_property_cells", "device-tree property-cell diagnostic string"
    if addr == "0x4cf4" and all(t in terms for t in ["aName", "aPhandle", "aDeviceType"]):
        return "dt_unflatten_device_tree_node", "device-tree node/property construction strings"
    return None


def unique_name(base: str, used: set[str]) -> str:
    if base not in used:
        used.add(base)
        return base
    i = 1
    while True:
        candidate = f"{base}_{i:02d}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        i += 1


def replace_symbols(repo: Path, renames: dict[str, str]) -> dict[str, int]:
    counts = {old: 0 for old in renames}
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.suffix not in {".c", ".h", ".S"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for old, new in sorted(renames.items(), key=lambda kv: len(kv[0]), reverse=True):
            text, n = re.subn(rf"\b{re.escape(old)}\b", new, text)
            counts[old] += n
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
    return counts


def apply(case_id: str, max_renames: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    fmap_path = s08 / "function-map.json"
    smap_path = s08 / "source-map.json"
    fmap = read_json(fmap_path)
    smap = read_json(smap_path)
    functions = fmap.get("functions", [])
    by_addr = {fn["address"].lower(): fn for fn in functions}
    used = {fn.get("source_symbol", "") for fn in functions}

    plan: list[dict[str, Any]] = []
    for row in read_jsonl(s08 / "diagnostic-summary-candidates.jsonl"):
        fn = by_addr.get(str(row.get("address", "")).lower())
        if not fn:
            continue
        old = fn.get("source_symbol", "")
        if not GENERIC_RE.fullmatch(old):
            continue
        classified = classify_candidate(row)
        if not classified:
            continue
        base, reason = classified
        new = unique_name(base, used)
        plan.append(
            {
                "address": fn["address"],
                "old_symbol": old,
                "new_symbol": new,
                "source_file": fn["source_file"],
                "module": fn.get("module"),
                "output_class": fn.get("output_class"),
                "candidate_risk": row.get("risk"),
                "reason": reason,
                "evidence": "S08/diagnostic-summary-candidates.jsonl",
                "boundary": "Candidate-driven semantic name only; output_class is not promoted.",
            }
        )
        if len(plan) >= max_renames:
            break

    renames = {row["old_symbol"]: row["new_symbol"] for row in plan}
    counts = replace_symbols(repo, renames)

    for row in plan:
        fn = by_addr[row["address"].lower()]
        fn["source_symbol"] = row["new_symbol"]
        fn["semantic_name"] = row["new_symbol"]
        fn.setdefault("evidence", []).append("S08/evidence-semantic-name-index.jsonl")
        row["occurrences_replaced"] = counts.get(row["old_symbol"], 0)

    for entry in smap.get("function_sources", []):
        symbol = entry.get("symbol") or entry.get("source_symbol")
        if symbol in renames:
            if "symbol" in entry:
                entry["symbol"] = renames[symbol]
            if "source_symbol" in entry:
                entry["source_symbol"] = renames[symbol]
            entry["semantic_name"] = renames[symbol]

    previous = read_jsonl(s08 / "evidence-semantic-name-index.jsonl")
    iteration_id = f"S08-CANDIDATE-NAME-RW{len({r.get('iteration_id') for r in previous if str(r.get('iteration_id', '')).startswith('S08-CANDIDATE-NAME')}) + 1}"
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

    fmap["candidate_semantic_name_iteration"] = iteration_id
    smap["candidate_semantic_name_iteration"] = iteration_id
    write_json(fmap_path, fmap)
    write_json(smap_path, smap)
    write_jsonl(s08 / "evidence-semantic-name-index.jsonl", previous + rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "requested_max": max_renames,
        "renamed_this_run": len(rows),
        "total_evidence_semantic_name_rows": len(previous) + len(rows),
        "occurrences_replaced_this_run": sum(row.get("occurrences_replaced", 0) for row in rows),
        "boundary": "Only names changed. No source body rewrite or output_class promotion was performed.",
    }
    write_json(s08 / "candidate-semantic-name-summary.json", summary)
    write_jsonl(s08 / "candidate-semantic-name-index.jsonl", rows)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-renames", type=int, default=20)
    args = ap.parse_args()
    print(json.dumps(apply(args.case_id, args.max_renames), ensure_ascii=False))


if __name__ == "__main__":
    main()
