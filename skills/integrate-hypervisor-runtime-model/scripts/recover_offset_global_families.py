#!/usr/bin/env python3
"""Recover corpus-wide offset families and global object candidates for S06.

This workflow-v2 helper mines IDA/Hex-Rays exports for repeated argument-base
field offsets and qword/dword/byte global references. It emits reviewable type
seeds only; it does not claim ownership or mutate IDA.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
WIDTHS = {
    "QWORD": 8,
    "DWORD": 4,
    "WORD": 2,
    "BYTE": 1,
    "unsigned __int64": 8,
    "__int64": 8,
    "unsigned int": 4,
    "int": 4,
    "unsigned __int16": 2,
    "__int16": 2,
    "char": 1,
    "_QWORD": 8,
    "_DWORD": 4,
    "_WORD": 2,
    "_BYTE": 1,
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
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def c_ident(value: str) -> str:
    value = re.sub(r"[^0-9A-Za-z_]+", "_", value.lower()).strip("_")
    if not value:
        return "unknown"
    if value[0].isdigit():
        return f"_{value}"
    return value


def module_from_source(source_file: str) -> str:
    stem = Path(source_file).stem
    if stem.startswith("cluster_"):
        return "unknown"
    return c_ident(stem)


def width_type(width: int) -> str:
    return {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}.get(width, "uintptr_t")


def confidence(count: int, func_count: int) -> str:
    if func_count >= 8 and count >= 20:
        return "medium"
    if func_count >= 3 and count >= 6:
        return "low-medium"
    return "low"


def extract_offset_accesses(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    patterns = [
        re.compile(r"\*\(_(QWORD|DWORD|WORD|BYTE)\s*\*\)\(([aA]\d)\s*\+\s*(\d+)(?:LL?)?\)"),
        re.compile(r"\*\((unsigned __int64|__int64|unsigned int|int|unsigned __int16|__int16|char)\s*\*\)\(([aA]\d)\s*\+\s*(\d+)(?:LL?)?\)"),
        re.compile(r"\*\(_(QWORD|DWORD|WORD|BYTE)\s*\*\)\(([aA]\d)\s*\+\s*(0x[0-9A-Fa-f]+)(?:LL?)?\)"),
        re.compile(r"\*\((unsigned __int64|__int64|unsigned int|int|unsigned __int16|__int16|char)\s*\*\)\(([aA]\d)\s*\+\s*(0x[0-9A-Fa-f]+)(?:LL?)?\)"),
    ]
    for pattern in patterns:
        for m in pattern.finditer(text):
            kind, base, off_text = m.group(1), m.group(2).lower(), m.group(3)
            offset = int(off_text, 16) if off_text.lower().startswith("0x") else int(off_text)
            width = WIDTHS.get(kind, 0)
            rows.append(
                {
                    "base": base,
                    "offset": offset,
                    "width": width,
                    "access_text": m.group(0),
                }
            )
    return rows


def extract_global_refs(text: str) -> list[str]:
    return re.findall(r"\b(?:qword|dword|word|byte)_[0-9A-Fa-f]+\b", text)


def infer_global_kind(name: str, modules: set[str], examples: list[str]) -> str:
    text = " ".join(examples)
    if name.startswith("byte_"):
        return "flag_or_byte_state"
    if name.startswith("dword_"):
        if any(token in text for token in ["cpu", "irq", "timer", "count", "nr_", "dword_96000"]):
            return "count_or_config_scalar"
        return "u32_global_state"
    if "timer" in modules:
        return "timer_global_state"
    if "interrupt" in modules:
        return "interrupt_global_state"
    if "cache" in modules or "mmu" in modules:
        return "memory_or_page_table_global"
    if "percpu" in modules:
        return "percpu_global_state"
    return "opaque_global_state"


def render_objects_header(structs: list[dict[str, Any]], globals_: list[dict[str, Any]]) -> str:
    lines = [
        "#ifndef RECOVERED_OBJECTS_H",
        "#define RECOVERED_OBJECTS_H",
        "",
        "#include <stdint.h>",
        "#include <stddef.h>",
        "",
        "/*",
        " * Candidate structures recovered from repeated Hex-Rays offset families.",
        " * These are review seeds: field names preserve offsets until stronger",
        " * ownership/type evidence exists.",
        " */",
        "",
    ]
    for st in structs:
        lines.append(f"/* evidence: {st['evidence_summary']}; confidence {st['confidence']} */")
        lines.append(f"struct {st['name']} {{")
        max_end = 1
        for field in st["fields"]:
            max_end = max(max_end, field["offset"] + max(1, field["width"]))
            lines.append(
                f"    /* candidate {width_type(max(1, field['width']))} field_0x{field['offset']:x}; "
                f"hits={field['access_count']}, funcs={field['function_count']} */"
            )
        lines.append(f"    uint8_t raw[0x{max_end:x}];")
        lines.append("};")
        lines.append("")
    lines.extend(
        [
            "struct recovered_global_candidate {",
            "    const char *name;",
            "    uintptr_t address;",
            "    const char *kind;",
            "    uint32_t reference_count;",
            "};",
            "",
            "/* Top global candidates are also recorded in S06/global-object-model.json. */",
        ]
    )
    for glob in globals_[:80]:
        lines.append(
            f"/* global {glob['name']} @ 0x{glob['address']:x}: {glob['kind']}, refs={glob['reference_count']}, funcs={glob['function_count']} */"
        )
    lines.extend(["", "#endif", ""])
    return "\n".join(lines)


def recover(case_id: str, max_structs: int, max_globals: int, emit_header: bool) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s06 = case / "stages" / "S06"
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    function_map = read_json(s08 / "function-map.json")["functions"]
    by_addr = {fn["address"]: fn for fn in function_map}
    decompile = read_json(s07 / "decompile-export-full.json")["functions"]

    family_hits: dict[tuple[str, str], dict[str, Any]] = {}
    global_hits: dict[str, dict[str, Any]] = {}
    arg_flow_rows: list[dict[str, Any]] = []

    for fn in decompile:
        addr = fn["address"]
        fmap = by_addr.get(addr, {})
        source_file = fmap.get("source_file", "recovered/unknown/unknown.c")
        module = fmap.get("module") or module_from_source(source_file)
        text = "\n".join(fn.get("pseudocode", {}).get("lines", []))

        for access in extract_offset_accesses(text):
            key = (source_file, access["base"])
            fam = family_hits.setdefault(
                key,
                {
                    "source_file": source_file,
                    "module": module,
                    "base": access["base"],
                    "offsets": defaultdict(lambda: {"count": 0, "widths": Counter(), "functions": set(), "examples": []}),
                    "functions": set(),
                },
            )
            off = access["offset"]
            fam["offsets"][off]["count"] += 1
            fam["offsets"][off]["widths"][access["width"]] += 1
            fam["offsets"][off]["functions"].add(addr)
            if len(fam["offsets"][off]["examples"]) < 3:
                fam["offsets"][off]["examples"].append(access["access_text"])
            fam["functions"].add(addr)
            arg_flow_rows.append(
                {
                    "function": addr,
                    "source_file": source_file,
                    "module": module,
                    "base": access["base"],
                    "offset": off,
                    "width": access["width"],
                    "access_text": access["access_text"],
                    "confidence": "low",
                    "reason": "Hex-Rays base+offset access",
                }
            )

        for name in extract_global_refs(text):
            addr_text = name.split("_", 1)[1]
            g = global_hits.setdefault(
                name,
                {
                    "name": name,
                    "address": int(addr_text, 16),
                    "reference_count": 0,
                    "functions": set(),
                    "modules": Counter(),
                    "source_files": Counter(),
                    "examples": [],
                },
            )
            g["reference_count"] += 1
            g["functions"].add(addr)
            g["modules"][module] += 1
            g["source_files"][source_file] += 1
            if len(g["examples"]) < 5:
                g["examples"].append(addr)

    struct_rows: list[dict[str, Any]] = []
    for (source_file, base), fam in family_hits.items():
        offsets = fam["offsets"]
        if len(offsets) < 3:
            continue
        module = fam["module"]
        fields = []
        for off, data in sorted(offsets.items()):
            width = data["widths"].most_common(1)[0][0] or 8
            fields.append(
                {
                    "offset": off,
                    "width": width,
                    "name": f"field_0x{off:x}",
                    "access_count": data["count"],
                    "function_count": len(data["functions"]),
                    "examples": data["examples"],
                    "confidence": confidence(data["count"], len(data["functions"])),
                }
            )
        total_count = sum(f["access_count"] for f in fields)
        funcs = len(fam["functions"])
        struct_rows.append(
            {
                "name": f"candidate_{c_ident(module)}_{base}_object",
                "source_file": source_file,
                "module": module,
                "base": base,
                "field_count": len(fields),
                "access_count": total_count,
                "function_count": funcs,
                "confidence": confidence(total_count, funcs),
                "fields": fields,
                "evidence_summary": f"{source_file}:{base} offsets={len(fields)} accesses={total_count} functions={funcs}",
                "boundary": "offset-family candidate; not ownership proof",
            }
        )
    struct_rows.sort(key=lambda r: (r["confidence"] != "medium", -r["access_count"], -r["field_count"], r["name"]))
    struct_rows = struct_rows[:max_structs]

    global_rows: list[dict[str, Any]] = []
    for name, g in global_hits.items():
        funcs = len(g["functions"])
        modules = set(g["modules"].keys())
        if g["reference_count"] < 5 or funcs < 2:
            continue
        global_rows.append(
            {
                "name": name,
                "address": g["address"],
                "reference_count": g["reference_count"],
                "function_count": funcs,
                "modules": [{"module": m, "count": c} for m, c in g["modules"].most_common()],
                "source_files": [{"source_file": s, "count": c} for s, c in g["source_files"].most_common(5)],
                "kind": infer_global_kind(name, modules, g["examples"]),
                "confidence": confidence(g["reference_count"], funcs),
                "examples": g["examples"],
                "boundary": "global candidate; not owner/lifetime proof",
            }
        )
    global_rows.sort(key=lambda r: (-r["reference_count"], -r["function_count"], r["name"]))
    global_rows = global_rows[:max_globals]

    write_jsonl(s06 / "struct-layouts.jsonl", struct_rows)
    write_jsonl(s06 / "argument-flow.jsonl", arg_flow_rows)
    write_json(
        s06 / "global-object-model.json",
        {
            "stage_id": "S06",
            "mode": "corpus-wide-offset-family",
            "status": "review_seed_ready",
            "objects": global_rows,
            "boundary": "Global candidates are frequency/type seeds only; ownership and lifecycle remain unresolved until proven.",
        },
    )
    write_json(
        s06 / "type-candidates.json",
        {
            "stage_id": "S06",
            "mode": "corpus-wide-offset-family",
            "function_count": len(function_map),
            "struct_candidate_count": len(struct_rows),
            "global_candidate_count": len(global_rows),
            "argument_flow_count": len(arg_flow_rows),
            "type_policy": "offset families and globals are review seeds; generated names preserve field offsets until stronger evidence exists",
        },
    )
    proposal = {
        "stage_id": "S06",
        "mode": "review-only",
        "struct_candidates": [row["name"] for row in struct_rows],
        "global_candidates": [row["name"] for row in global_rows[:100]],
        "ida_write_policy": "do not apply automatically; proposals require human/transaction review",
    }
    write_json(s06 / "ida-type-proposal.json", proposal)
    summary = {
        "case_id": case_id,
        "stage_id": "S06",
        "iteration_id": "S06-OFFSET-GLOBAL-RW1",
        "generated_at": now_iso(),
        "struct_candidate_count": len(struct_rows),
        "global_candidate_count": len(global_rows),
        "argument_flow_count": len(arg_flow_rows),
        "top_structs": [
            {"name": row["name"], "access_count": row["access_count"], "field_count": row["field_count"], "confidence": row["confidence"]}
            for row in struct_rows[:10]
        ],
        "top_globals": [
            {"name": row["name"], "reference_count": row["reference_count"], "kind": row["kind"], "confidence": row["confidence"]}
            for row in global_rows[:20]
        ],
        "boundary": "S06 review seeds only; no IDA writes and no ownership claims.",
    }
    write_json(s06 / "offset-global-recovery-summary.json", summary)

    if emit_header and repo.exists():
        header = render_objects_header(struct_rows[:40], global_rows[:80])
        header_path = repo / "include" / "recovered" / "recovered_objects.h"
        header_path.parent.mkdir(parents=True, exist_ok=True)
        header_path.write_text(header, encoding="utf-8", newline="\n")
        runtime_header = repo / "include" / "recovered" / "recovered_runtime.h"
        if runtime_header.exists():
            text = runtime_header.read_text(encoding="utf-8")
            include = '#include "recovered/recovered_objects.h"\n'
            if include not in text:
                text = text.replace("#include <stddef.h>\n", "#include <stddef.h>\n\n" + include, 1)
                runtime_header.write_text(text, encoding="utf-8", newline="\n")
        summary["emitted_header"] = str(header_path.relative_to(ROOT)).replace("\\", "/")
        write_json(s06 / "offset-global-recovery-summary.json", summary)

    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-structs", type=int, default=120)
    ap.add_argument("--max-globals", type=int, default=250)
    ap.add_argument("--emit-header", action="store_true")
    args = ap.parse_args()
    print(json.dumps(recover(args.case_id, args.max_structs, args.max_globals, args.emit_header), ensure_ascii=False))


if __name__ == "__main__":
    main()
