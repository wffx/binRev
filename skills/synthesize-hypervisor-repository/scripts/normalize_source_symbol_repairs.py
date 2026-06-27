#!/usr/bin/env python3
"""Normalize source-symbol repair wrappers into ordinary lifted source views.

Source-symbol repair wrappers are emergency coverage restorations.  They make
S09 readback pass, but they are poor user-facing source because they lack the
normal lifted pseudocode review block.  This pass uses S07/decompile-export-
full.json to replace repair wrappers with ordinary recovered source blocks:

- preserve function-map source symbol, output_class, confidence, and source;
- restore Hex-Rays pseudocode under a non-compiling review block;
- keep the executable body conservative and traceable;
- remove the `source-symbol repair:` marker so S09 tracks this as normal
  lifted/wrapper debt rather than emergency repair debt.

It does not promote output_class and does not invent semantic logic.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
EVIDENCE_RE = re.compile(r"/\* evidence: image offset 0x[0-9a-fA-F]+, IDA ")


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


def find_function_end(text: str, def_start: int) -> int:
    brace = text.find("{", def_start)
    if brace < 0:
        return def_start
    depth = 0
    idx = brace
    while idx < len(text):
        ch = text[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                idx += 1
                while idx < len(text) and text[idx] in " \t\r\n":
                    idx += 1
                return idx
        idx += 1
    return len(text)


def find_block_start(text: str, def_start: int) -> int:
    matches = list(EVIDENCE_RE.finditer(text, 0, def_start))
    if not matches:
        return text.rfind("\n", 0, def_start) + 1
    start = matches[-1].start()
    while start > 0 and text[start - 1] in "\r\n":
        start -= 1
    return start


def source_symbol_def_re(symbol: str) -> re.Pattern[str]:
    return re.compile(r"(^|\n)uintptr_t\s+" + re.escape(symbol) + r"\s*\(", re.MULTILINE)


def pseudocode_lines(decomp: dict[str, Any]) -> list[str]:
    pseudo = decomp.get("pseudocode") or {}
    if isinstance(pseudo, dict) and pseudo.get("ok") and isinstance(pseudo.get("lines"), list):
        return [str(line) for line in pseudo["lines"]]
    if isinstance(pseudo, str):
        return pseudo.splitlines()
    return []


def mark_for_class(output_class: str | None) -> str:
    return {
        "semantic-c": "recovered_mark_semantic",
        "lifted-c": "recovered_mark_lifted",
        "asm-fallback": "recovered_mark_asm_fallback",
    }.get(output_class or "lifted-c", "recovered_mark_lifted")


def render_block(fn: dict[str, Any], decomp: dict[str, Any]) -> str:
    symbol = fn["source_symbol"]
    addr = fn["address"].lower()
    start, end = fn.get("range", [addr, fn.get("end", addr)])
    output_class = fn.get("output_class", "lifted-c")
    confidence = fn.get("confidence", "medium")
    ida_name = fn.get("ida_name") or decomp.get("ida_name")
    mark = mark_for_class(output_class)
    lines = pseudocode_lines(decomp)
    if lines:
        pseudo = "\n".join(lines)
        review = (
            "/* lifted Hex-Rays review restored from S07/decompile-export-full.json; "
            f"source body remains {output_class}. */\n"
            "#if 0 /* lifted Hex-Rays pseudocode: review and semantic-rewrite before compiling */\n"
            f"{pseudo}\n"
            "#endif\n"
        )
    else:
        review = (
            "/* lifted Hex-Rays review unavailable in S07/decompile-export-full.json; "
            f"source body remains {output_class}. */\n"
        )
    return f"""/* evidence: image offset {addr}, IDA {ida_name}, range {start}-{end}, confidence {confidence}, class {output_class} */
{review}uintptr_t {symbol}(struct recovered_context *ctx)
{{
    /* evidence: original IDA name {ida_name}, image offset {addr}; normalized from source-symbol repair using S07 pseudocode evidence. */
    {mark}(ctx);
    recovered_trace(ctx, \"{symbol}\", {addr}ULL);
    return 0;
}}
"""


def normalize(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    fmap = read_json(s08 / "function-map.json")
    fn_by_addr = {fn["address"].lower(): fn for fn in fmap.get("functions", [])}
    decomp_obj = read_json(s07 / "decompile-export-full.json")
    decomp_by_addr = {fn["address"].lower(): fn for fn in decomp_obj.get("functions", [])}
    repair_rows = read_jsonl(s08 / "source-symbol-repair-index.jsonl")

    by_source: dict[str, list[dict[str, Any]]] = {}
    for row in repair_rows:
        addr = str(row.get("address", "")).lower()
        source = row.get("source")
        symbol = row.get("symbol")
        if not addr or not source or not symbol:
            continue
        by_source.setdefault(source, []).append({"address": addr, "symbol": symbol})

    rows: list[dict[str, Any]] = []
    normalized = 0
    skipped = 0
    for source, items in by_source.items():
        path = repo / source
        if not path.exists():
            skipped += len(items)
            for item in items:
                rows.append({**item, "source": source, "normalized": False, "reason": "source_file_missing"})
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        replacements: list[tuple[int, int, str, dict[str, Any]]] = []
        for item in items:
            symbol = item["symbol"]
            addr = item["address"]
            fn = fn_by_addr.get(addr)
            decomp = decomp_by_addr.get(addr)
            if not fn:
                skipped += 1
                rows.append({**item, "source": source, "normalized": False, "reason": "function_map_missing"})
                continue
            if not decomp:
                skipped += 1
                rows.append({**item, "source": source, "normalized": False, "reason": "decompile_export_missing"})
                continue
            match = source_symbol_def_re(symbol).search(text)
            if not match:
                skipped += 1
                rows.append({**item, "source": source, "normalized": False, "reason": "symbol_not_found"})
                continue
            start = find_block_start(text, match.start())
            end = find_function_end(text, match.start())
            old_block = text[start:end]
            if "source-symbol repair:" not in old_block:
                skipped += 1
                rows.append({**item, "source": source, "normalized": False, "reason": "not_a_repair_block"})
                continue
            new_block = render_block(fn, decomp)
            replacements.append((start, end, new_block, item))

        for start, end, new_block, item in sorted(replacements, reverse=True):
            text = text[:start].rstrip() + "\n\n" + new_block + "\n" + text[end:].lstrip()
            rows.append(
                {
                    **item,
                    "source": source,
                    "normalized": True,
                    "reason": "restored_lifted_pseudocode_view_from_s07",
                    "pseudocode_line_count": len(pseudocode_lines(decomp_by_addr[item["address"]])),
                    "boundary": "Readability normalization only; output_class and source ownership unchanged.",
                }
            )
            normalized += 1
        path.write_text(text.rstrip() + "\n", encoding="utf-8", newline="\n")

    enriched = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-SOURCE-SYMBOL-REPAIR-NORMALIZE-RW1",
            "generated_at": now_iso(),
        }
        for row in rows
    ]
    write_jsonl(s08 / "source-symbol-repair-normalization-index.jsonl", enriched)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-SOURCE-SYMBOL-REPAIR-NORMALIZE-RW1",
        "normalized": normalized,
        "skipped": skipped,
        "input_repair_rows": len(repair_rows),
        "decompile_export": "S07/decompile-export-full.json",
        "boundary": "Normalized emergency repair wrappers into ordinary lifted source views without semantic promotion.",
    }
    write_json(s08 / "source-symbol-repair-normalization-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    print(json.dumps(normalize(args.case_id), ensure_ascii=False))


if __name__ == "__main__":
    main()
