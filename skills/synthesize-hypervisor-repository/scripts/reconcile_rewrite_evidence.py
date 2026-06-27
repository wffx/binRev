#!/usr/bin/env python3
"""Reconcile S08 rewrite indexes back into function/source maps.

Use after semantic rewrite batches, especially if a batch was interrupted or
multiple scripts touched S08 artifacts. The script treats rewrite indexes as
the source of truth for applied source-body rewrites and updates:

- S08/function-map.json
- S08/source-map.json
- S08/source-quality-report.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]

INDEX_FLAGS = {
    "semantic-rewrite-index.jsonl": ("semantic_rewrite", "S08/semantic-rewrite-index.jsonl"),
    "arm64-arch-rewrite-index.jsonl": ("arm64_arch_rewrite", "S08/arm64-arch-rewrite-index.jsonl"),
    "percpu-rewrite-index.jsonl": ("percpu_rewrite", "S08/percpu-rewrite-index.jsonl"),
    "boot-rewrite-index.jsonl": ("boot_rewrite", "S08/boot-rewrite-index.jsonl"),
    "sysreg-rewrite-index.jsonl": ("sysreg_rewrite", "S08/sysreg-rewrite-index.jsonl"),
    "log-sequence-rewrite-index.jsonl": ("log_sequence_rewrite", "S08/log-sequence-rewrite-index.jsonl"),
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def reconcile(case_id: str) -> dict[str, Any]:
    s08 = ROOT / "cases" / case_id / "stages" / "S08"
    function_map_path = s08 / "function-map.json"
    source_map_path = s08 / "source-map.json"
    quality_path = s08 / "source-quality-report.json"

    function_map_doc = read_json(function_map_path)
    source_map_doc = read_json(source_map_path)
    functions = function_map_doc["functions"]
    by_addr = {fn["address"]: fn for fn in functions}

    applied: dict[str, list[tuple[str, str]]] = {}
    index_rows = 0
    for index_name, (flag, evidence_path) in INDEX_FLAGS.items():
        for row in read_jsonl(s08 / index_name):
            if not row.get("applied"):
                continue
            addr = row.get("address")
            if not addr:
                continue
            applied.setdefault(addr, []).append((flag, evidence_path))
            index_rows += 1

    updated_functions = 0
    for addr, flags in applied.items():
        fn = by_addr.get(addr)
        if not fn:
            continue
        before = json.dumps(fn, sort_keys=True)
        fn["output_class"] = "semantic-c"
        fn["confidence"] = "high"
        evidence = fn.setdefault("evidence", [])
        for flag, evidence_path in flags:
            fn[flag] = "applied"
            if evidence_path not in evidence:
                evidence.append(evidence_path)
        if json.dumps(fn, sort_keys=True) != before:
            updated_functions += 1

    updated_sources = 0
    for entry in source_map_doc.get("function_sources", []):
        if entry.get("function") in applied:
            if entry.get("output_class") != "semantic-c":
                updated_sources += 1
            entry["output_class"] = "semantic-c"

    counts = {"semantic-c": 0, "lifted-c": 0, "asm-fallback": 0}
    for fn in functions:
        cls = fn.get("output_class")
        if cls in counts:
            counts[cls] += 1
    quality = read_json(quality_path)
    quality["source_class_counts"] = counts
    quality["generated_source_function_count"] = sum(counts.values())
    quality["rewrite_reconcile_policy"] = "Applied rewrite indexes are reconciled into function-map/source-map/source-quality before S09/S10."

    function_map_doc["rewrite_reconcile_iteration"] = "S08-REWRITE-RECONCILE-RW1"
    source_map_doc["rewrite_reconcile_iteration"] = "S08-REWRITE-RECONCILE-RW1"
    write_json(function_map_path, function_map_doc)
    write_json(source_map_path, source_map_doc)
    write_json(quality_path, quality)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-REWRITE-RECONCILE-RW1",
        "applied_index_rows": index_rows,
        "applied_function_addresses": len(applied),
        "updated_functions": updated_functions,
        "updated_source_map_entries": updated_sources,
        "source_class_counts": counts,
    }
    write_json(s08 / "rewrite-reconcile-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    print(json.dumps(reconcile(args.case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
