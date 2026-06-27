#!/usr/bin/env python3
"""Apply S06 global-object aliases to user-facing source files.

This is a presentation/readability pass. It replaces high-frequency IDA global
tokens such as qword_108280 in .c files with stable semantic aliases derived
from S06/global-object-model.json. Original IDA global names remain in S06/S08
evidence and in recovered_objects.h comments.
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


def c_ident(value: str) -> str:
    value = re.sub(r"[^0-9A-Za-z_]+", "_", value.lower()).strip("_")
    if not value:
        return "global_state"
    if value[0].isdigit():
        return f"_{value}"
    return value


def alias_base(kind: str, name: str) -> str:
    if kind == "flag_or_byte_state":
        return "global_flag_state"
    if kind == "count_or_config_scalar" or name.startswith("dword_"):
        return "global_config_scalar"
    if kind == "timer_global_state":
        return "timer_global_state"
    if kind == "interrupt_global_state":
        return "interrupt_global_state"
    if kind == "memory_or_page_table_global":
        return "memory_global_state"
    if kind == "percpu_global_state":
        return "percpu_global_state"
    return c_ident(kind)


def build_aliases(objects: list[dict[str, Any]], max_aliases: int, min_refs: int) -> list[dict[str, Any]]:
    counters: dict[str, int] = defaultdict(int)
    rows: list[dict[str, Any]] = []
    for obj in objects:
        refs = int(obj.get("reference_count", 0))
        if refs < min_refs:
            continue
        original = obj["name"]
        base = alias_base(obj.get("kind", ""), original)
        counters[base] += 1
        alias = f"{base}_{counters[base]:03d}"
        rows.append(
            {
                "original": original,
                "alias": alias,
                "address": obj.get("address"),
                "kind": obj.get("kind"),
                "reference_count": refs,
                "function_count": obj.get("function_count"),
                "confidence": obj.get("confidence"),
                "boundary": "presentation alias only; original IDA global name remains in evidence",
            }
        )
        if len(rows) >= max_aliases:
            break
    return rows


def replace_in_source(repo: Path, aliases: list[dict[str, Any]]) -> dict[str, Any]:
    mapping = {row["original"]: row["alias"] for row in aliases}
    counts = {row["original"]: 0 for row in aliases}
    file_counts: dict[str, int] = {}
    # Replace only C source. Headers keep original alias evidence comments.
    for path in sorted(repo.rglob("*.c")):
        text = path.read_text(encoding="utf-8", errors="replace")
        original_text = text
        changed = 0
        for old, new in sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True):
            text, n = re.subn(rf"\b{re.escape(old)}\b", new, text)
            if n:
                counts[old] += n
                changed += n
        if text != original_text:
            path.write_text(text, encoding="utf-8", newline="\n")
            file_counts[path.relative_to(repo).as_posix()] = changed
    return {"counts": counts, "file_counts": file_counts}


def append_alias_header(repo: Path, aliases: list[dict[str, Any]]) -> None:
    header = repo / "include" / "recovered" / "recovered_objects.h"
    if not header.exists():
        return
    text = header.read_text(encoding="utf-8")
    marker_begin = "/* Global presentation aliases generated from S06. */"
    if marker_begin in text:
        text = text.split(marker_begin, 1)[0].rstrip() + "\n\n#endif\n"
    block = [marker_begin]
    for row in aliases:
        block.append(
            f"/* {row['alias']} aliases {row['original']} @ 0x{int(row['address']):x}; "
            f"kind={row['kind']}; refs={row['reference_count']}; confidence={row['confidence']} */"
        )
    block.append("")
    text = text.replace("\n#endif\n", "\n" + "\n".join(block) + "#endif\n", 1)
    header.write_text(text, encoding="utf-8", newline="\n")


def apply_aliases(case_id: str, max_aliases: int, min_refs: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s06 = case / "stages" / "S06"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    objects = read_json(s06 / "global-object-model.json").get("objects", [])
    aliases = build_aliases(objects, max_aliases=max_aliases, min_refs=min_refs)
    replace_report = replace_in_source(repo, aliases)
    for row in aliases:
        row["occurrences_replaced"] = replace_report["counts"].get(row["original"], 0)
    append_alias_header(repo, aliases)

    rows = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-GLOBAL-ALIAS-RW1",
            "generated_at": now_iso(),
        }
        for row in aliases
    ]
    write_jsonl(s08 / "global-alias-index.jsonl", rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-GLOBAL-ALIAS-RW1",
        "requested_max": max_aliases,
        "min_refs": min_refs,
        "aliases": len(aliases),
        "aliases_with_replacements": sum(1 for row in aliases if row.get("occurrences_replaced", 0) > 0),
        "total_occurrences_replaced": sum(row.get("occurrences_replaced", 0) for row in aliases),
        "file_counts": replace_report["file_counts"],
        "boundary": "Presentation aliases only. Original qword/dword/byte names remain in S06/S08 evidence and recovered_objects.h.",
    }
    write_json(s08 / "global-alias-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-aliases", type=int, default=160)
    ap.add_argument("--min-refs", type=int, default=10)
    args = ap.parse_args()
    print(json.dumps(apply_aliases(args.case_id, args.max_aliases, args.min_refs), ensure_ascii=False))


if __name__ == "__main__":
    main()
