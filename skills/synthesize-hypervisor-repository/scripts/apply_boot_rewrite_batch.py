#!/usr/bin/env python3
"""Apply conservative boot/init semantic rewrites.

This S08 helper targets small ARM64 boot functions with clear entry/handoff
semantics: DAIF masking, CurrentEL/MPIDR checks, WFE waits, and short boot call
chains. Complex CPU/device/platform initialization remains lifted-c.
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def normalize_addr(addr: str) -> str:
    return hex(int(addr, 16))


def symbol_for_sub(call: str, addr_to_symbol: dict[str, str]) -> str | None:
    m = re.fullmatch(r"sub_([0-9A-Fa-f]+)", call)
    if not m:
        return None
    return addr_to_symbol.get(hex(int(m.group(1), 16)))


def parse_mask(mask: str) -> str:
    text = mask.rstrip("uU")
    if text.lower().startswith("0x"):
        value = int(text, 16)
    elif re.fullmatch(r"[0-9]+", text):
        value = int(text, 10)
    else:
        value = int(text, 16)
    return f"{value}ULL"


def classify_boot_body(lines: list[str], addr: str, addr_to_symbol: dict[str, str]) -> dict[str, Any] | None:
    inner = [line.strip() for line in lines[2:-1] if line.strip()]
    body = "\n".join(inner)
    if not inner or len(inner) > 16:
        return None

    actions: list[str] = []
    evidence: list[str] = []
    terminal = f"recovered_boot_handoff(ctx, \"boot_handoff\", {addr}ULL)"
    kind = None

    if "CurrentEL" in body and "__wfe" in body:
        actions.append('    recovered_boot_sysreg(ctx, "CurrentEL");')
        actions.append('    recovered_boot_wait_event(ctx, "unsupported exception level wait");')
        evidence.append("CurrentEL/WFE exception-level guard")
        kind = "boot_currentel_guard"
        return {"kind": kind, "actions": actions, "terminal_return": "0ULL", "evidence_statements": evidence}

    if "MPIDR_EL1" in body and "__wfe" in body and len(inner) <= 14:
        actions.append('    recovered_boot_daif(ctx, "DAIFSet", 15ULL);')
        actions.append('    recovered_boot_sysreg(ctx, "MPIDR_EL1");')
        actions.append('    recovered_boot_wait_event(ctx, "secondary CPU release wait");')
        for call in re.findall(r"\bsub_[0-9A-Fa-f]+\b", body):
            target = symbol_for_sub(call, addr_to_symbol)
            if target:
                actions.append(f"    (void){target}(ctx);")
        evidence.append("MPIDR_EL1/WFE secondary boot wait")
        kind = "boot_secondary_wait"
        return {"kind": kind, "actions": actions, "terminal_return": terminal, "evidence_statements": evidence}

    if "DAIFSet" in body and len(inner) <= 12:
        kind = "boot_daif_call_chain"
        for stmt in inner:
            m = re.search(r"MSR\s+DAIF(Set|Clr), #(?:0x)?([0-9A-Fa-f]+)", stmt)
            if m:
                op = "DAIFSet" if m.group(1) == "Set" else "DAIFClr"
                actions.append(f"    recovered_boot_daif(ctx, \"{op}\", {parse_mask(m.group(2))});")
                evidence.append(stmt)
                continue
            if "_ReadStatusReg(DAIF)" in stmt:
                actions.append('    recovered_boot_sysreg(ctx, "DAIF");')
                evidence.append(stmt)
                continue
            if "_ReadStatusReg(TPIDR_EL2)" in stmt:
                actions.append('    recovered_boot_sysreg(ctx, "TPIDR_EL2");')
                evidence.append(stmt)
                continue
            if "__dmb" in stmt:
                actions.append('    recovered_arm64_barrier(ctx, "DMB", 11ULL);')
                evidence.append(stmt)
                continue
            m = re.search(r"\b(sub_[0-9A-Fa-f]+)\(", stmt)
            if m:
                target = symbol_for_sub(m.group(1), addr_to_symbol)
                if target:
                    if stmt.startswith("return "):
                        terminal = f"{target}(ctx)"
                    else:
                        actions.append(f"    (void){target}(ctx);")
                    evidence.append(stmt)
        if evidence:
            return {"kind": kind, "actions": actions, "terminal_return": terminal, "evidence_statements": evidence}

    if "ELR_EL2" in body and len(inner) <= 6:
        actions.append('    recovered_boot_sysreg(ctx, "ELR_EL2");')
        if "__dsb" in body:
            actions.append('    recovered_arm64_barrier(ctx, "DSB", 15ULL);')
        if "DAIFClr" in body:
            actions.append('    recovered_boot_daif(ctx, "DAIFClr", 4ULL);')
        for call in re.findall(r"\bsub_[0-9A-Fa-f]+\b", body):
            target = symbol_for_sub(call, addr_to_symbol)
            if target:
                terminal = f"{target}(ctx)"
        return {
            "kind": "boot_elr_handoff",
            "actions": actions,
            "terminal_return": terminal,
            "evidence_statements": ["ELR_EL2 handoff"],
        }

    return None


def rewrite_function_body(text: str, symbol: str, addr: str, rewrite: dict[str, Any]) -> tuple[str, bool]:
    pattern = re.compile(
        rf"uintptr_t\s+{re.escape(symbol)}\(struct recovered_context \*ctx\)\s*\{{\n"
        rf"    /\* evidence: original IDA name .*? image offset {re.escape(addr)} \*/\n"
        rf"    recovered_mark_(?:lifted|semantic)\(ctx\);\n"
        rf"    recovered_trace\(ctx, \"{re.escape(symbol)}\", {re.escape(addr)}ULL\);\n"
        rf"    return 0;\n"
        rf"\}}",
        re.DOTALL,
    )
    actions = "\n".join(rewrite["actions"])
    body = (
        f"uintptr_t {symbol}(struct recovered_context *ctx)\n"
        "{\n"
        f"    /* boot semantic rewrite: {rewrite['kind']} */\n"
        f"    recovered_trace(ctx, \"{symbol}\", {addr}ULL);\n"
        f"{actions}\n"
        f"    return {rewrite['terminal_return']};\n"
        "}"
    )
    new_text, count = pattern.subn(body, text, count=1)
    return new_text, count == 1


def update_quality_report(path: Path, function_map: list[dict[str, Any]]) -> None:
    report = read_json(path)
    counts = {"semantic-c": 0, "lifted-c": 0, "asm-fallback": 0}
    for fn in function_map:
        cls = fn.get("output_class")
        if cls in counts:
            counts[cls] += 1
    report["source_class_counts"] = counts
    report["generated_source_function_count"] = sum(counts.values())
    report["boot_rewrite_policy"] = "small boot DAIF/EL/MPIDR/WFE handoff helpers may promote to semantic-c only when wrapper bodies are replaced."
    write_json(path, report)


def apply_batch(case_id: str, source_file: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo_roots = [ROOT / "recovered-repos" / case_id / "recovered-hypervisor", s08 / "recovered-hypervisor"]

    function_map_path = s08 / "function-map.json"
    function_map_doc = read_json(function_map_path)
    function_map = function_map_doc["functions"]
    addr_to_symbol = {normalize_addr(fn["address"]): fn["source_symbol"] for fn in function_map}
    decompile = {normalize_addr(fn["address"]): fn for fn in read_json(s07 / "decompile-export-full.json")["functions"]}

    selected: list[dict[str, Any]] = []
    skipped = 0
    for fn in function_map:
        if fn["source_file"] != source_file:
            continue
        if fn.get("boot_rewrite") == "applied":
            continue
        dec = decompile.get(normalize_addr(fn["address"]))
        lines = dec.get("pseudocode", {}).get("lines", []) if dec else []
        rewrite = classify_boot_body(lines, fn["address"], addr_to_symbol)
        if not rewrite:
            skipped += 1
            continue
        selected.append({"function": fn, "rewrite": rewrite})
        if len(selected) >= max_functions:
            break

    applied: list[dict[str, Any]] = []
    for root in repo_roots:
        path = root / source_file
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        for item in selected:
            fn = item["function"]
            rewrite = item["rewrite"]
            text, ok = rewrite_function_body(text, fn["source_symbol"], fn["address"], rewrite)
            if root == repo_roots[0]:
                applied.append(
                    {
                        "address": fn["address"],
                        "source_symbol": fn["source_symbol"],
                        "source_file": source_file,
                        "rewrite_kind": rewrite["kind"],
                        "statements": rewrite["evidence_statements"],
                        "applied": ok,
                    }
                )
        path.write_text(text, encoding="utf-8", newline="\n")

    applied_by_addr = {row["address"]: row for row in applied if row["applied"]}
    for fn in function_map:
        row = applied_by_addr.get(fn["address"])
        if not row:
            continue
        fn["output_class"] = "semantic-c"
        fn["confidence"] = "high" if row["rewrite_kind"] in {"boot_currentel_guard", "boot_elr_handoff"} else "medium"
        fn["boot_rewrite"] = "applied"
        fn.setdefault("evidence", []).append("S08/boot-rewrite-index.jsonl")

    function_map_doc["boot_rewrite_iteration"] = "S08-BOOT-RW1"
    write_json(function_map_path, function_map_doc)
    update_quality_report(s08 / "source-quality-report.json", function_map)

    index_path = s08 / "boot-rewrite-index.jsonl"
    prior: list[dict[str, Any]] = []
    if index_path.exists():
        prior = [json.loads(line) for line in index_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows = prior + [
        {**row, "case_id": case_id, "stage_id": "S08", "iteration_id": "S08-BOOT-RW1", "generated_at": now_iso()}
        for row in applied
    ]
    write_jsonl(index_path, rows)

    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-BOOT-RW1",
        "source_file": source_file,
        "requested_max": max_functions,
        "selected": len(selected),
        "applied_this_batch": sum(1 for row in applied if row["applied"]),
        "applied_cumulative": sum(1 for row in rows if row.get("applied")),
        "skipped_before_limit": skipped,
        "rewrite_kinds": {},
        "boundary": "Only small boot DAIF/EL/MPIDR/WFE/handoff helpers were rewritten; complex boot initialization remains lifted-c.",
    }
    for row in applied:
        if row["applied"]:
            summary["rewrite_kinds"][row["rewrite_kind"]] = summary["rewrite_kinds"].get(row["rewrite_kind"], 0) + 1
    write_json(s08 / "boot-rewrite-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file", required=True)
    ap.add_argument("--max-functions", type=int, default=50)
    args = ap.parse_args()
    print(json.dumps(apply_batch(args.case_id, args.source_file, args.max_functions), ensure_ascii=False))


if __name__ == "__main__":
    main()
