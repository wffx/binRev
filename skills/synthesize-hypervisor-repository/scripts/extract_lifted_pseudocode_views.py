#!/usr/bin/env python3
"""Move lifted Hex-Rays review blocks out of user-facing source.

The corpus lift originally keeps a large `#if 0` decompiler view beside many
lifted wrappers. That is useful for audit, but it makes the delivered source
look like an IDA dump. This pass preserves the review text in S08 evidence and
replaces the inline block with a compact pointer comment.

This is a presentation pass only. It does not promote functions or change
their output_class.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]


FUNC_DEF_RE = re.compile(r"^uintptr_t\s+(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s*\(", flags=re.MULTILINE)
IF_MARKER = "#if 0 /* lifted Hex-Rays pseudocode: review and semantic-rewrite before compiling */"


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
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def extract(case_id: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    function_map = read_json(s08 / "function-map.json")["functions"]
    by_symbol = {fn["source_symbol"]: fn for fn in function_map if fn.get("source_symbol")}

    previous = read_jsonl(s08 / "lifted-pseudocode-review.jsonl")
    already = {(row.get("source_file"), row.get("source_symbol")) for row in previous}
    moved: list[dict[str, Any]] = []
    externalized_existing = 0
    remaining = max_functions

    for path in sorted(repo.rglob("*.c")):
        if remaining <= 0:
            break
        rel = path.relative_to(repo).as_posix()
        text = path.read_text(encoding="utf-8", errors="replace")
        changed = False

        removals: list[tuple[int, int, str, dict[str, Any], str]] = []
        for match in FUNC_DEF_RE.finditer(text):
            if remaining <= 0:
                break
            symbol = match.group("symbol")
            fn = by_symbol.get(symbol)
            if remaining <= 0 or not fn:
                continue
            func_start = match.start()
            prefix = text[:func_start]
            endif_pos = prefix.rstrip().rfind("\n#endif")
            if endif_pos < 0:
                continue
            after_endif = prefix[endif_pos + len("\n#endif") :]
            if "uintptr_t " in after_endif or IF_MARKER in after_endif:
                # Never cross another function or another pseudocode block.
                continue
            if_pos = prefix.rfind(IF_MARKER, 0, endif_pos)
            if if_pos < 0:
                continue
            block = text[if_pos : endif_pos + len("\n#endif")]
            if "uintptr_t " in block or "/* evidence: image offset" in block:
                continue
            pseudocode = text[if_pos + len(IF_MARKER) : endif_pos].strip("\r\n")
            if (rel, symbol) in already:
                externalized_existing += 1
            else:
                moved.append(
                    {
                        "case_id": case_id,
                        "stage_id": "S08",
                        "iteration_id": "S08-LIFTED-PSEUDOCODE-EXTRACT-RW1",
                        "generated_at": now_iso(),
                        "address": fn.get("address"),
                        "ida_name": fn.get("ida_name"),
                        "source_symbol": symbol,
                        "source_file": rel,
                        "output_class": fn.get("output_class"),
                        "pseudocode": pseudocode,
                        "boundary": "Moved from user-facing source only; function output_class is unchanged.",
                    }
                )
            replacement = (
                "/* lifted Hex-Rays review moved to "
                f"S08/lifted-pseudocode-review.jsonl; function remains {fn.get('output_class')}. */\n"
            )
            removals.append((if_pos, endif_pos + len("\n#endif"), replacement, fn, symbol))
            remaining -= 1
            changed = True

        new_text = text
        for start, end, replacement, _fn, _symbol in sorted(removals, reverse=True):
            new_text = new_text[:start] + replacement + new_text[end:].lstrip("\r\n")
        if changed:
            path.write_text(new_text, encoding="utf-8", newline="\n")

    all_rows = previous + moved
    write_jsonl(s08 / "lifted-pseudocode-review.jsonl", all_rows)
    by_file: dict[str, int] = {}
    for row in moved:
        by_file[row["source_file"]] = by_file.get(row["source_file"], 0) + 1
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-LIFTED-PSEUDOCODE-EXTRACT-RW1",
        "generated_at": now_iso(),
        "requested_max": max_functions,
        "moved_this_run": len(moved),
        "externalized_existing_this_run": externalized_existing,
        "moved_cumulative": len(all_rows),
        "file_counts": by_file,
        "boundary": "Presentation cleanup only. Pseudocode evidence is externalized; output_class is unchanged.",
    }
    write_json(s08 / "lifted-pseudocode-review-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-functions", type=int, default=500)
    args = ap.parse_args()
    print(json.dumps(extract(args.case_id, args.max_functions), ensure_ascii=False))


if __name__ == "__main__":
    main()
