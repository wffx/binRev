#!/usr/bin/env python3
"""Move already-named functions into a more source-like module file.

This pass improves repository organization without changing function bodies,
names, or output classes.  It is intentionally conservative and currently
supports a single reviewed family: device-tree helpers named `dt_*`.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
TARGETS = {
    "dt_": {
        "source": "platform/unknown/device_tree.c",
        "module": "device_tree",
        "header": """#include <stdint.h>
#include <stddef.h>

#include \"recovered/recovered_runtime.h\"

/* Corpus-wide recovered source for device-tree helpers.
 * Functions in this file were rehomed from generic runtime output only after
 * evidence-backed `dt_*` naming.  Lifted functions remain lifted-c.
 */

""",
        "match": lambda symbol: symbol.startswith("dt_"),
    },
    "diagnostics": {
        "source": "core/runtime/diagnostics.c",
        "module": "diagnostics",
        "header": """#include <stdint.h>
#include <stddef.h>

#include \"recovered/recovered_runtime.h\"

/* Corpus-wide recovered source for runtime diagnostics.
 * Functions in this file were rehomed from generic runtime output after
 * evidence-backed diagnostic names or summaries.  Lifted functions remain
 * lifted-c.
 */

""",
        "match": lambda symbol: (
            symbol.startswith("runtime_print_")
            or symbol.startswith("runtime_show_")
            or symbol.startswith("runtime_handle_debug_key")
            or symbol.startswith("runtime_request_")
            or symbol.startswith("runtime_dump_")
            or symbol.startswith("interrupt_report_")
        ),
    },
    "scheduler": {
        "source": "core/scheduler/credit.c",
        "module": "scheduler",
        "header": """#include <stdint.h>
#include <stddef.h>

#include \"recovered/recovered_runtime.h\"

/* Corpus-wide recovered source for scheduler helpers.
 * Functions in this file were rehomed after evidence-backed scheduler names.
 */

""",
        "match": lambda symbol: symbol.startswith("scheduler_"),
    },
    "boot": {
        "source": "arch/arm64/boot/boot.c",
        "module": "boot",
        "header": "",
        "match": lambda symbol: symbol in {"boot_enable_nonboot_cpus"},
    }
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def function_block_pattern(symbol: str) -> re.Pattern[str]:
    return re.compile(
        r"(?P<preamble>"
        r"(?:/\* evidence: image offset [^\n]+\*/\n)"
        r"(?:/\* lifted Hex-Rays review moved to [^\n]+\*/\n)?"
        r"(?:(?:#if 0 /\* lifted Hex-Rays pseudocode: review and semantic-rewrite before compiling \*/\n).*?\n#endif\n)?"
        r"(?:\n)?)"
        rf"(?P<func>uintptr_t\s+{re.escape(symbol)}\s*\(struct recovered_context \*ctx\)\s*\{{.*?\n\}})\n*",
        flags=re.DOTALL,
    )


def refresh_source_file_lists(repo: Path, source_map: dict[str, Any], delivery: dict[str, Any]) -> None:
    files = [
        {"path": p.relative_to(repo).as_posix(), "size": p.stat().st_size}
        for p in sorted(repo.rglob("*"))
        if p.is_file()
    ]
    source_map["source_files"] = files
    delivery["files"] = files
    delivery["contains_c"] = any(row["path"].endswith(".c") for row in files)
    delivery["contains_h"] = any(row["path"].endswith(".h") for row in files)
    delivery["forbidden_artifact_count"] = sum(
        1 for row in files if Path(row["path"]).suffix.lower() in {".json", ".jsonl", ".sqlite", ".i64", ".idb"}
    )


def rehome(case_id: str, family: str) -> dict[str, Any]:
    if family not in TARGETS:
        raise SystemExit(f"unsupported family: {family}")

    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    fmap_path = s08 / "function-map.json"
    smap_path = s08 / "source-map.json"
    delivery_path = s08 / "source-repo-delivery.json"
    quality_path = s08 / "source-quality-report.json"

    fmap = read_json(fmap_path)
    smap = read_json(smap_path)
    delivery = read_json(delivery_path)
    quality = read_json(quality_path)
    target = TARGETS[family]
    target_rel = target["source"]
    target_path = repo / target_rel

    moved_blocks: list[tuple[dict[str, Any], str]] = []
    rows: list[dict[str, Any]] = []
    candidates = [fn for fn in fmap.get("functions", []) if target["match"](str(fn.get("source_symbol", "")))]
    by_source: dict[str, list[dict[str, Any]]] = {}
    for fn in candidates:
        if fn.get("source_file") == target_rel:
            rows.append(
                {
                    "address": fn["address"],
                    "symbol": fn["source_symbol"],
                    "old_source": target_rel,
                    "new_source": target_rel,
                    "output_class": fn.get("output_class"),
                    "moved": False,
                    "already_rehomed": True,
                    "reason": f"{family} already in target source",
                }
            )
        else:
            by_source.setdefault(fn["source_file"], []).append(fn)

    for source_rel, fns in by_source.items():
        path = repo / source_rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for fn in fns:
            symbol = fn["source_symbol"]
            match = function_block_pattern(symbol).search(text)
            if not match:
                rows.append(
                    {
                        "address": fn["address"],
                        "symbol": symbol,
                        "old_source": source_rel,
                        "new_source": target_rel,
                        "moved": False,
                        "reason": "function_block_not_found",
                    }
                )
                continue
            block = match.group("preamble") + match.group("func") + "\n\n"
            text = text[: match.start()] + text[match.end() :]
            moved_blocks.append((fn, block))
            rows.append(
                {
                    "address": fn["address"],
                    "symbol": symbol,
                    "old_source": source_rel,
                    "new_source": target_rel,
                    "output_class": fn.get("output_class"),
                    "moved": True,
                    "reason": f"{family} evidence-backed source organization",
                }
            )
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")

    if moved_blocks:
        existing = target_path.read_text(encoding="utf-8", errors="replace") if target_path.exists() else target["header"]
        if not existing.endswith("\n\n"):
            existing = existing.rstrip() + "\n\n"
        existing_symbols = set(re.findall(r"uintptr_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", existing))
        additions = []
        for fn, block in moved_blocks:
            if fn["source_symbol"] not in existing_symbols:
                additions.append(block)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(existing + "".join(additions), encoding="utf-8", newline="\n")

    moved_addrs = {fn["address"].lower() for fn, _ in moved_blocks}
    for fn in fmap.get("functions", []):
        if fn["address"].lower() in moved_addrs:
            fn["source_file"] = target_rel
            fn["module"] = target["module"]
            fn.setdefault("evidence", []).append("S08/module-rehome-index.jsonl")
    for entry in smap.get("function_sources", []):
        if str(entry.get("function", "")).lower() in moved_addrs:
            entry["source"] = target_rel

    refresh_source_file_lists(repo, smap, delivery)
    quality["source_files"] = len(smap.get("source_files", []))
    quality["module_rehome_policy"] = "Only already named prefix families may be rehomed; output_class and body are unchanged."
    fmap["module_rehome_iteration"] = "S08-MODULE-REHOME-RW1"
    smap["module_rehome_iteration"] = "S08-MODULE-REHOME-RW1"

    write_json(fmap_path, fmap)
    write_json(smap_path, smap)
    write_json(delivery_path, delivery)
    write_json(quality_path, quality)
    enriched_rows = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": "S08-MODULE-REHOME-RW1",
            "generated_at": now_iso(),
            "boundary": "Source organization only; no body/class/name semantic promotion.",
        }
        for row in rows
    ]
    previous_rows = read_jsonl(s08 / "module-rehome-index.jsonl")
    dedup: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in previous_rows + enriched_rows:
        key = (str(row.get("address")), str(row.get("new_source")), str(row.get("reason")))
        dedup[key] = row
    cumulative_rows = list(dedup.values())
    write_jsonl(s08 / "module-rehome-index.jsonl", cumulative_rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-MODULE-REHOME-RW1",
        "family": family,
        "target_source": target_rel,
        "moved": len(moved_blocks),
        "already_rehomed": len([row for row in rows if row.get("already_rehomed")]),
        "failed": len([row for row in rows if not row.get("moved") and not row.get("already_rehomed")]),
        "cumulative_index_rows": len(cumulative_rows),
        "source_file_count": quality["source_files"],
        "boundary": "Directory/source-file organization only; output_class remains unchanged.",
    }
    write_json(s08 / "module-rehome-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--prefix", dest="family", default=None, help="Deprecated alias for --family.")
    ap.add_argument("--family", default=None)
    args = ap.parse_args()
    print(json.dumps(rehome(args.case_id, args.family or args.prefix or "dt_"), ensure_ascii=False))


if __name__ == "__main__":
    main()
