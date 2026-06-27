#!/usr/bin/env python3
"""Clean inline Hex-Rays review blocks for semantic source functions.

Corpus-lifted repositories keep Hex-Rays pseudocode inline for auditability.
Once a function has evidence-backed semantic body/name, the inline pseudocode
can be removed from the user-facing source file because S07/S08 evidence keeps
the trace. This reduces visible `sub_`, `qword_`, and `vNN` residue in code.
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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def clean_case(case_id: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    function_map = read_json(s08 / "function-map.json")["functions"]

    candidates = [
        fn
        for fn in function_map
        if fn.get("output_class") == "semantic-c"
        and (
            fn.get("semantic_rewrite") == "applied"
            or fn.get("arm64_arch_rewrite") == "applied"
            or fn.get("percpu_rewrite") == "applied"
            or fn.get("boot_rewrite") == "applied"
            or fn.get("sysreg_rewrite") == "applied"
            or fn.get("log_sequence_rewrite") == "applied"
            or str(fn.get("ida_name", "")).startswith("nullsub_")
        )
    ][:max_functions]

    removed: list[dict[str, Any]] = []
    by_file: dict[str, list[dict[str, Any]]] = {}
    for fn in candidates:
        by_file.setdefault(fn["source_file"], []).append(fn)

    for rel, fns in by_file.items():
        path = repo / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for fn in fns:
            symbol = fn["source_symbol"]
            def_pattern = f"uintptr_t {symbol}(struct recovered_context *ctx)"
            def_pos = text.find(def_pattern)
            if def_pos < 0:
                continue
            endif_pos = text.rfind("\n#endif", 0, def_pos)
            if endif_pos < 0:
                continue
            between = text[endif_pos + len("\n#endif") : def_pos]
            if between.strip():
                continue
            if_pos = text.rfind(
                "#if 0 /* lifted Hex-Rays pseudocode: review and semantic-rewrite before compiling */",
                0,
                endif_pos,
            )
            if if_pos < 0:
                continue
            block = text[if_pos:endif_pos]
            if "uintptr_t " in block or "/* evidence: image offset" in block:
                continue
            text = text[:if_pos] + text[endif_pos + len("\n#endif") :]
            removed.append(
                {
                    "address": fn["address"],
                    "source_symbol": fn["source_symbol"],
                    "source_file": rel,
                    "reason": "semantic body has evidence-backed rewrite; full pseudocode remains in S07 decompile export",
                }
            )
        path.write_text(text, encoding="utf-8", newline="\n")

    index_path = s08 / "source-view-cleanup-index.jsonl"
    previous = read_jsonl(index_path)
    iteration_id = f"S08-SOURCE-VIEW-CLEAN-RW{len({row.get('iteration_id') for row in previous if row.get('iteration_id')}) + 1}"
    new_rows = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": iteration_id,
            "generated_at": now_iso(),
        }
        for row in removed
    ]
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "generated_at": now_iso(),
        "requested_max": max_functions,
        "cleaned_this_run": len(removed),
        "cleaned_cumulative": len(previous) + len(new_rows),
        "boundary": "Only semantic functions with applied rewrite/name evidence had inline pseudocode removed from user-facing source. Evidence remains in S07/S08 artifacts.",
    }
    write_json(s08 / "source-view-cleanup-summary.json", summary)
    index_path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in previous + new_rows),
        encoding="utf-8",
    )
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-functions", type=int, default=500)
    args = ap.parse_args()
    print(json.dumps(clean_case(args.case_id, args.max_functions), ensure_ascii=False))


if __name__ == "__main__":
    main()
