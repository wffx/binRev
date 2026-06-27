#!/usr/bin/env python3
"""Plan semantic rewrite batches for a corpus-lifted recovered repository.

This S09 helper ranks source files by readability debt. It does not edit source;
it only creates a next-batch plan for S08 semantic rewrite work.
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

WRAPPER_RE = re.compile(r"\brecovered_mark_(?:lifted|semantic)\s*\(")
PSEUDOCODE_RE = re.compile(r"lifted Hex-Rays pseudocode")
IDA_RESIDUE_RE = re.compile(r"\b(?:sub_[0-9A-Fa-f]+|qword_[0-9A-Fa-f]+|dword_[0-9A-Fa-f]+|v\d+)\b")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def classify_priority(stats: dict[str, Any]) -> str:
    if stats.get("semantic_labeled_wrapper_mismatch", 0) >= 25:
        return "P0"
    if stats["semantic_functions"] == 0 and stats["function_count"] >= 50:
        return "P0"
    if stats["lifted_functions"] >= 100 or stats["ida_residue_count"] >= 5000:
        return "P0"
    if stats["lifted_functions"] >= 25 or stats["ida_residue_count"] >= 1000:
        return "P1"
    if stats["lifted_functions"] > 0:
        return "P2"
    return "P3"


def recommended_action(stats: dict[str, Any]) -> str:
    module = stats["module"]
    if module in {"mmu", "stage2", "cache"}:
        return "Translate sysreg/TLB/cache/page-table helpers first; introduce typed EL2/MMU wrappers and page descriptor structs."
    if module in {"timer", "interrupt"}:
        return "Translate GIC/timer paths first; introduce IRQ/timer register helpers and interrupt descriptor names."
    if module in {"boot", "percpu"}:
        return "Translate initialization and per-CPU helpers first; introduce boot context and per-CPU state structs."
    if module == "runtime":
        return "Start with high fan-in helpers and string-adjacent functions; split generic runtime utilities before large semantic rewrites."
    return "Keep as lifted-c until caller/callee neighborhoods provide stronger names and types."


def plan(case_id: str, top: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    s09 = case / "stages" / "S09"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    function_map = read_json(s08 / "function-map.json")["functions"]
    readability_path = s09 / "readability-report.json"
    readability = read_json(readability_path) if readability_path.exists() else {}

    by_file: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "source_file": "",
            "module": "",
            "function_count": 0,
            "semantic_functions": 0,
            "lifted_functions": 0,
            "asm_fallback_functions": 0,
            "wrapper_count": 0,
            "pseudocode_view_count": 0,
            "ida_residue_count": 0,
            "addresses": [],
        }
    )
    for fn in function_map:
        path = fn["source_file"]
        stats = by_file[path]
        stats["source_file"] = path
        stats["module"] = fn.get("module", "unknown")
        stats["function_count"] += 1
        stats["addresses"].append(fn["address"])
        output_class = fn.get("output_class")
        if output_class == "semantic-c":
            stats["semantic_functions"] += 1
        elif output_class == "lifted-c":
            stats["lifted_functions"] += 1
        elif output_class == "asm-fallback":
            stats["asm_fallback_functions"] += 1

    for rel, stats in by_file.items():
        text_path = repo / rel
        text = text_path.read_text(encoding="utf-8", errors="replace") if text_path.exists() else ""
        stats["wrapper_count"] = len(WRAPPER_RE.findall(text))
        stats["pseudocode_view_count"] = len(PSEUDOCODE_RE.findall(text))
        stats["ida_residue_count"] = len(IDA_RESIDUE_RE.findall(text))
        stats["semantic_ratio"] = stats["semantic_functions"] / stats["function_count"] if stats["function_count"] else 0.0
        stats["wrapper_ratio"] = stats["wrapper_count"] / stats["function_count"] if stats["function_count"] else 0.0
        stats["pseudocode_view_ratio"] = stats["pseudocode_view_count"] / stats["function_count"] if stats["function_count"] else 0.0
        stats["semantic_labeled_wrapper_mismatch"] = min(stats["semantic_functions"], stats["wrapper_count"])
        stats["debt_score"] = (
            stats["lifted_functions"] * 10
            + stats["wrapper_count"] * 8
            + min(stats["ida_residue_count"], 10000) / 20
            - stats["semantic_functions"] * 3
            + stats["semantic_labeled_wrapper_mismatch"] * 12
        )
        stats["priority"] = classify_priority(stats)
        stats["recommended_action"] = recommended_action(stats)
        stats["sample_addresses"] = stats["addresses"][:12]
        del stats["addresses"]

    ordered = sorted(by_file.values(), key=lambda item: item["debt_score"], reverse=True)
    batches = []
    for idx, stats in enumerate(ordered[:top], 1):
        batches.append(
            {
                "batch": f"semantic-rw-{idx:02d}",
                "priority": stats["priority"],
                "source_file": stats["source_file"],
                "module": stats["module"],
                "target_functions": min(max(stats["lifted_functions"], stats["semantic_labeled_wrapper_mismatch"]), 50),
                "reason": {
                    "function_count": stats["function_count"],
                    "lifted_functions": stats["lifted_functions"],
                    "semantic_labeled_wrapper_mismatch": stats["semantic_labeled_wrapper_mismatch"],
                    "semantic_ratio": stats["semantic_ratio"],
                    "wrapper_ratio": stats["wrapper_ratio"],
                    "ida_residue_count": stats["ida_residue_count"],
                },
                "sample_addresses": stats["sample_addresses"],
                "recommended_action": stats["recommended_action"],
                "exit_condition": "Reduce wrapper bodies for this file, lower IDA residue, and promote evidence-backed functions from lifted-c to semantic-c without inventing unresolved logic.",
            }
        )

    result = {
        "case_id": case_id,
        "stage_id": "S09",
        "iteration_id": "S09-SEMANTIC-REWRITE-PLAN-RW1",
        "generated_at": now_iso(),
        "status": readability.get("status", "unknown"),
        "readability_ratios": readability.get("ratios", {}),
        "module_count": len(ordered),
        "files": ordered,
        "recommended_batches": batches,
        "boundary": "This plan ranks semantic rewrite targets only. It must not use Oracle data and must not rewrite source by itself.",
    }
    write_json(s09 / "semantic-rewrite-plan.json", result)

    lines = [
        "# S09 Semantic Rewrite Plan",
        "",
        f"Case: `{case_id}`",
        "",
        f"Status: `{result['status']}`",
        "",
        "## Recommended batches",
        "",
    ]
    for batch in batches:
        reason = batch["reason"]
        lines.extend(
            [
                f"### {batch['batch']}: `{batch['source_file']}`",
                "",
                f"- Priority: `{batch['priority']}`",
                f"- Module: `{batch['module']}`",
                f"- Target lifted functions this batch: `{batch['target_functions']}`",
                f"- Function count: `{reason['function_count']}`",
                f"- Lifted functions: `{reason['lifted_functions']}`",
                f"- Semantic-labeled wrapper mismatch: `{reason['semantic_labeled_wrapper_mismatch']}`",
                f"- Semantic ratio: `{reason['semantic_ratio']:.2%}`",
                f"- Wrapper ratio: `{reason['wrapper_ratio']:.2%}`",
                f"- IDA residue count: `{reason['ida_residue_count']}`",
                f"- Sample addresses: `{', '.join(batch['sample_addresses'])}`",
                f"- Action: {batch['recommended_action']}",
                "",
            ]
        )
    write_text(s09 / "semantic-rewrite-plan.md", "\n".join(lines))
    return result


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--top", type=int, default=8)
    args = ap.parse_args()
    result = plan(args.case_id, args.top)
    print(
        json.dumps(
            {
                "case": args.case_id,
                "status": result["status"],
                "module_count": result["module_count"],
                "batches": len(result["recommended_batches"]),
                "top": result["recommended_batches"][0]["source_file"] if result["recommended_batches"] else None,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
