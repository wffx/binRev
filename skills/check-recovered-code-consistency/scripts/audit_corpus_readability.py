#!/usr/bin/env python3
"""Audit corpus-wide recovered source readability.

This is a workflow-v2 S09 helper. It measures whether the recovered source is
still merely a coverage-first lift or has become a readable semantic repo.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]

GENERIC_SOURCE_SYMBOL_RE = re.compile(
    r"\b(?:(?:runtime_helper|boot_helper|cache_helper|mmu_helper|mmu_switch_or_enable|percpu_access|timer_event|timer_control|interrupt_helper|interrupt_route|exception_helper|stage2_helper|unknown_helper)_\d{4}|(?:runtime_access_current_cpu_state|percpu_access_current_cpu_state|boot_access_current_cpu_state|arm64_cache_tlb_maintenance)(?:_\d+)?)\b"
)
IDA_SOURCE_SYMBOL_RE = re.compile(r"\b(?:sub_[0-9A-Fa-f]+|nullsub_\d+)\b")

PATTERNS = {
    "ida_sub_name": re.compile(r"\bsub_[0-9A-Fa-f]+\b"),
    "ida_nullsub_name": re.compile(r"\bnullsub_\d+\b"),
    "ida_loc_name": re.compile(r"\bloc(?:ret)?_[0-9A-Fa-f]+\b"),
    "ida_global_name": re.compile(r"\b[qd]word_[0-9A-Fa-f]+\b"),
    "ida_temp_var": re.compile(r"\bv\d+\b"),
    "address_literal": re.compile(r"\b0x[0-9A-Fa-f]{3,}\b"),
    "generic_helper_symbol": GENERIC_SOURCE_SYMBOL_RE,
    "trace_call": re.compile(r"\brecovered_trace\s*\("),
    "wrapper_marker": re.compile(r"\brecovered_mark_(?:lifted|semantic|asm_fallback)\s*\("),
    "pseudocode_view": re.compile(r"lifted Hex-Rays pseudocode"),
    "lifted_marker": re.compile(r"\brecovered_mark_lifted\s*\("),
    "semantic_marker": re.compile(r"\brecovered_mark_semantic\s*\("),
    "asm_marker": re.compile(r"\brecovered_mark_asm_fallback\s*\("),
    "source_symbol_repair": re.compile(r"source-symbol repair:"),
}


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def scan_file(path: Path, repo: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    counts = {name: len(pattern.findall(text)) for name, pattern in PATTERNS.items()}
    function_defs = len(re.findall(r"^uintptr_t\s+[A-Za-z_][A-Za-z0-9_]*\s*\(", text, flags=re.MULTILINE))
    return {
        "path": path.relative_to(repo).as_posix(),
        "lines": len(lines),
        "function_defs": function_defs,
        "counts": counts,
    }


def audit(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    s09 = case / "stages" / "S09"
    delivery = read_json(s08 / "source-repo-delivery.json")
    quality = read_json(s08 / "source-quality-report.json")
    source_map = read_json(s08 / "source-map.json")
    function_map_path = s08 / "function-map.json"
    function_map = read_json(function_map_path).get("functions", []) if function_map_path.exists() else []
    external_pseudocode_summary_path = s08 / "lifted-pseudocode-review-summary.json"
    external_pseudocode_summary = (
        read_json(external_pseudocode_summary_path) if external_pseudocode_summary_path.exists() else {}
    )
    repo = ROOT / delivery["canonical_source_repo"]

    c_files = sorted(repo.rglob("*.c"))
    file_reports = [scan_file(path, repo) for path in c_files]
    totals: dict[str, int] = {name: 0 for name in PATTERNS}
    total_functions = 0
    total_lines = 0
    for report in file_reports:
        total_functions += report["function_defs"]
        total_lines += report["lines"]
        for name, count in report["counts"].items():
            totals[name] += count

    generated_functions = quality.get("generated_source_function_count") or len(source_map.get("function_sources", []))
    semantic = quality.get("source_class_counts", {}).get("semantic-c", 0)
    lifted = quality.get("source_class_counts", {}).get("lifted-c", 0)
    asm = quality.get("source_class_counts", {}).get("asm-fallback", 0)
    semantic_ratio = semantic / max(1, generated_functions)
    lifted_ratio = lifted / max(1, generated_functions)
    wrapper_ratio = totals["wrapper_marker"] / max(1, generated_functions)
    repair_wrapper_count = totals["source_symbol_repair"]
    repair_wrapper_ratio = repair_wrapper_count / max(1, generated_functions)
    normal_wrapper_count = max(0, totals["wrapper_marker"] - repair_wrapper_count)
    normal_wrapper_ratio = normal_wrapper_count / max(1, generated_functions)
    trace_ratio = totals["trace_call"] / max(1, generated_functions)
    pseudocode_view_ratio = totals["pseudocode_view"] / max(1, generated_functions)
    external_pseudocode_count = int(external_pseudocode_summary.get("moved_cumulative", 0) or 0)
    pseudocode_evidence_ratio = (totals["pseudocode_view"] + external_pseudocode_count) / max(1, generated_functions)
    generic_helper_ratio = totals["generic_helper_symbol"] / max(1, generated_functions)
    generic_source_symbol_count = sum(
        1 for fn in function_map if GENERIC_SOURCE_SYMBOL_RE.fullmatch(fn.get("source_symbol", ""))
    )
    generic_source_symbol_ratio = generic_source_symbol_count / max(1, len(function_map) or generated_functions)
    ida_source_symbol_count = sum(
        1 for fn in function_map if IDA_SOURCE_SYMBOL_RE.fullmatch(fn.get("source_symbol", ""))
    )
    ida_source_symbol_ratio = ida_source_symbol_count / max(1, len(function_map) or generated_functions)
    residue_score = (
        totals["ida_sub_name"]
        + totals["ida_nullsub_name"]
        + totals["ida_loc_name"]
        + totals["ida_global_name"]
        + totals["ida_temp_var"]
        + totals["generic_helper_symbol"]
    )

    blockers = []
    if semantic_ratio < 0.6:
        blockers.append(
            {
                "id": "READABILITY-SEMANTIC-RATIO",
                "severity": "blocker",
                "summary": "semantic-c ratio is below source_repo_ready threshold",
                "value": semantic_ratio,
                "threshold": 0.6,
            }
        )
    if wrapper_ratio > 0.25:
        blockers.append(
            {
                "id": "READABILITY-WRAPPER-RATIO",
                "severity": "blocker",
                "summary": "too many functions are still generic wrapper bodies",
                "value": wrapper_ratio,
                "threshold": 0.25,
            }
        )
    if repair_wrapper_count > 0:
        blockers.append(
            {
                "id": "READABILITY-SOURCE-SYMBOL-REPAIR",
                "severity": "blocker",
                "summary": "source-symbol repair wrappers remain; replace them with normal lifted or semantic recovery",
                "value": repair_wrapper_count,
                "threshold": 0,
            }
        )
    if pseudocode_evidence_ratio < 0.8:
        blockers.append(
            {
                "id": "READABILITY-PSEUDOCODE-VIEW",
                "severity": "blocker",
                "summary": "too few functions retain lifted pseudocode evidence for human review",
                "value": pseudocode_evidence_ratio,
                "threshold": 0.8,
            }
        )
    if residue_score > generated_functions:
        blockers.append(
            {
                "id": "READABILITY-IDA-RESIDUE",
                "severity": "warning",
                "summary": "IDA temporary/global/name residue remains high",
                "value": residue_score,
                "threshold": generated_functions,
            }
        )
    if generic_source_symbol_ratio > 0.5:
        blockers.append(
            {
                "id": "READABILITY-GENERIC-HELPER-NAMES",
                "severity": "blocker",
                "summary": "too many exported source symbols still use generic helper/access names",
                "value": generic_source_symbol_ratio,
                "threshold": 0.5,
            }
        )
    if ida_source_symbol_ratio > 0:
        blockers.append(
            {
                "id": "READABILITY-IDA-SOURCE-NAMES",
                "severity": "blocker",
                "summary": "primary source symbols still expose IDA address/nullsub-style names",
                "value": ida_source_symbol_ratio,
                "threshold": 0,
            }
        )

    status = "source_repo_ready" if not blockers else "source_corpus_lifted"
    report = {
        "case_id": case_id,
        "stage_id": "S09",
        "iteration_id": "S09-READABILITY-RW1",
        "status": status,
        "canonical_source_repo": delivery["canonical_source_repo"],
        "generated_source_function_count": generated_functions,
        "source_class_counts": {
            "semantic-c": semantic,
            "lifted-c": lifted,
            "asm-fallback": asm,
        },
        "ratios": {
            "semantic_ratio": semantic_ratio,
            "lifted_ratio": lifted_ratio,
            "wrapper_ratio": wrapper_ratio,
            "normal_wrapper_ratio": normal_wrapper_ratio,
            "source_symbol_repair_ratio": repair_wrapper_ratio,
            "trace_ratio": trace_ratio,
            "pseudocode_view_ratio": pseudocode_view_ratio,
            "external_pseudocode_ratio": external_pseudocode_count / max(1, generated_functions),
            "pseudocode_evidence_ratio": pseudocode_evidence_ratio,
            "generic_helper_occurrence_ratio": generic_helper_ratio,
            "generic_source_symbol_ratio": generic_source_symbol_ratio,
            "ida_source_symbol_ratio": ida_source_symbol_ratio,
        },
        "external_pseudocode_view_count": external_pseudocode_count,
        "normal_wrapper_count": normal_wrapper_count,
        "source_symbol_repair_wrapper_count": repair_wrapper_count,
        "generic_source_symbol_count": generic_source_symbol_count,
        "ida_source_symbol_count": ida_source_symbol_count,
        "residue_counts": totals,
        "source_function_defs_detected": total_functions,
        "source_line_count": total_lines,
        "file_reports": file_reports,
        "readiness_blockers": blockers,
        "next_refinement_targets": [
            "apply cluster-specific semantic rewrites for high-volume lifted-c modules",
            "replace generic recovered_mark wrapper bodies with translated Hex-Rays logic where safe",
            "replace source-symbol repair wrappers with normal lifted/semantic source bodies",
            "promote repeated qword/dword offset families into named globals/struct fields",
            "reduce IDA temporary variable residue in comments and bodies",
            "replace generic helper/access source names with evidence-backed semantic names",
        ],
    }
    write_json(s09 / "readability-report.json", report)
    md = f"""# S09 Readability Audit

Status: `{status}`

- Generated functions: `{generated_functions}`
- semantic-c: `{semantic}` ({semantic_ratio:.2%})
- lifted-c: `{lifted}` ({lifted_ratio:.2%})
- asm-fallback: `{asm}`
- wrapper-body ratio: `{wrapper_ratio:.2%}`
- normal wrapper-body ratio: `{normal_wrapper_ratio:.2%}`
- source-symbol repair wrapper ratio: `{repair_wrapper_ratio:.2%}` (`{repair_wrapper_count}` functions)
- generic helper-name occurrence ratio: `{generic_helper_ratio:.2%}`
- generic source-symbol ratio: `{generic_source_symbol_ratio:.2%}`
- IDA/address source-symbol ratio: `{ida_source_symbol_ratio:.2%}`
- traceability-call ratio: `{trace_ratio:.2%}`
- inline pseudocode view ratio: `{pseudocode_view_ratio:.2%}`
- external pseudocode evidence ratio: `{external_pseudocode_count / max(1, generated_functions):.2%}`
- total pseudocode evidence ratio: `{pseudocode_evidence_ratio:.2%}`
- IDA residue score: `{residue_score}`

## Readiness blockers

{chr(10).join('- `' + b['id'] + '`: ' + b['summary'] for b in blockers) if blockers else '- none'}

## Next refinement targets

- Apply semantic rewrites to high-volume lifted-c modules.
- Replace generic recovered_mark wrapper bodies with safe translated Hex-Rays logic.
- Replace source-symbol repair wrappers with normal lifted/semantic source bodies.
- Promote repeated global/offset families into named objects and structs.
- Replace generic helper/access symbols with evidence-backed semantic names.
"""
    write_text(s09 / "readability-report.md", md)
    return report


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    report = audit(args.case_id)
    print(json.dumps({"case": args.case_id, "status": report["status"], "blockers": len(report["readiness_blockers"])}, ensure_ascii=False))


if __name__ == "__main__":
    main()
