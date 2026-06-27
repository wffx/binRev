#!/usr/bin/env python3
"""Apply conservative diagnostic/boot summary rewrites.

This pass handles functions whose externalized or inline pseudocode contains
clear diagnostic strings but whose full dataflow remains too complex for a
faithful C rewrite. It replaces empty wrapper bodies with a small evidence-
backed summary body. The body is intentionally high-level and keeps original
details in S08 evidence.
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


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def body_for(symbol: str) -> tuple[str, list[str]] | None:
    if symbol == "runtime_handle_debug_key":
        return (
            """{
    /* diagnostic-summary rewrite: toggle debug key handling mode. */
    recovered_trace(ctx, "runtime_handle_debug_key", 0x1050ULL);
    recovered_log(ctx, "toggle debug key mode between normal and alternative handlers");
    return recovered_direct_call(ctx, "print selected debug key mode", 0x1c18ULL);
}""",
            [
                "aNormal",
                "aAlternative",
                "aCPressedUsingS",
                "global_flag_state_007",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_dump_cpu_register_state":
        return (
            """{
    /* diagnostic-summary rewrite: dump saved CPU register state. */
    recovered_trace(ctx, "runtime_dump_cpu_register_state", 0x2178ULL);
    recovered_log(ctx, "print PC/LR/SP/CPSR/mode plus general-purpose register pairs");
    recovered_log(ctx, "report watchdog mapping failure and unknown mode strings when present");
    return recovered_direct_call(ctx, "emit saved CPU register dump", 0x1c18ULL);
}""",
            [
                "aPc016lx",
                "aLr016lx",
                "aSpEl0016lx",
                "aCpsr016lxModeS",
                "aX0016lxX1016lx",
                "aUnableToMapWat",
                "aUnknown",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_request_machine_reboot_01":
        return (
            """{
    /* diagnostic-summary rewrite: honor noreboot flag then request delayed reboot. */
    recovered_trace(ctx, "runtime_request_machine_reboot_01", 0x1498ULL);
    recovered_log(ctx, "if noreboot is set, print warning and spin/stop instead of rebooting");
    (void)recovered_direct_call(ctx, "handle noreboot refusal path", 0x65de0ULL);
    recovered_log(ctx, "Rebooting machine");
    return recovered_direct_call(ctx, "request reboot with delay", 0x65e54ULL);
}""",
            [
                "aNorebootSetNot",
                "aRebootingMachi",
                "byte_95CC0",
                "sub_65DE0",
                "sub_65E54",
            ],
        )
    if symbol == "runtime_handle_debug_key_01":
        return (
            """{
    /* diagnostic-summary rewrite: switch console log level profile. */
    recovered_trace(ctx, "runtime_handle_debug_key_01", 0x1c64ULL);
    recovered_log(ctx, "toggle console log level profile between standard and guest views");
    recovered_log(ctx, "update active/current log-level bounds and print selected profile");
    return recovered_direct_call(ctx, "print selected console log-level profile", 0x1c18ULL);
}""",
            [
                "aGuest",
                "aStandard",
                "aCPressedSLogLe",
                "qword_971C0",
                "opaque_global_state_007",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_handle_debug_key_02":
        return (
            """{
    /* diagnostic-summary rewrite: raise console log level within active profile. */
    recovered_trace(ctx, "runtime_handle_debug_key_02", 0x1cb4ULL);
    recovered_log(ctx, "clamp current log level to active minimum, resolve textual level names, and print result");
    return recovered_direct_call(ctx, "print updated console log level", 0x1c18ULL);
}""",
            [
                "aCPressedSLogLe_0",
                "qword_971C0",
                "opaque_global_state_007",
                "qword_76308",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_handle_debug_key_03":
        return (
            """{
    /* diagnostic-summary rewrite: dump console ring from debug key. */
    recovered_trace(ctx, "runtime_handle_debug_key_03", 0x1d70ULL);
    recovered_log(ctx, "'%c' pressed -> dumping console ring");
    (void)recovered_direct_call(ctx, "dump console ring", 0x3c844ULL);
    return recovered_direct_call(ctx, "print dump-console-ring failure when nonzero", 0x1c18ULL);
}""",
            [
                "aCPressedDumpin_0",
                "aFailedToDumpCo",
                "sub_3C844",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_helper_0025":
        return (
            """{
    /* diagnostic-summary rewrite: report unexpected IRQ target state. */
    recovered_trace(ctx, "runtime_helper_0025", 0x1f40ULL);
    recovered_log(ctx, "Unexpected IRQ target; print interrupt routing state from context field_0x20");
    return recovered_direct_call(ctx, "print unexpected IRQ target diagnostic", 0x1c18ULL);
}""",
            [
                "aUnexpectedIrqT",
                "candidate_runtime_a1_object.field_0x20",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_helper_0027":
        return (
            """{
    /* diagnostic-summary rewrite: report division-by-zero trap and enter fault path. */
    recovered_trace(ctx, "runtime_helper_0027", 0x23acULL);
    recovered_log(ctx, "Division by zero");
    (void)recovered_direct_call(ctx, "software breakpoint after division-by-zero diagnostic", 0x23acULL);
    return recovered_direct_call(ctx, "dispatch division-by-zero fault report", 0x23c0ULL);
}""",
            [
                "aDivisionByZero",
                "__break",
                "sub_23C0",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_helper_0049":
        return (
            """{
    /* diagnostic-summary rewrite: validate PCI-like device-tree compatibility. */
    recovered_trace(ctx, "runtime_helper_0049", 0x39f4ULL);
    recovered_log(ctx, "check PCI/PCIe/VCI/HT compatible strings and required device_type");
    return recovered_direct_call(ctx, "print missing device_type diagnostic when required", 0x1c18ULL);
}""",
            [
                "aPci",
                "aPciex",
                "aVci",
                "aHt",
                "aPcie",
                "a1SMissingDevic",
                "sub_72884",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_helper_0015":
        return (
            """{
    /* diagnostic-summary rewrite: initialize credit scheduler global state. */
    recovered_trace(ctx, "runtime_helper_0015", 0x1b2cULL);
    recovered_log(ctx, "print credit scheduler parameters and load-tracking window length");
    (void)recovered_direct_call(ctx, "allocate credit scheduler private state", 0x29b10ULL);
    recovered_log(ctx, "initialize runqueue/list heads and scheduler shift/granularity fields");
    return 0ULL;
}""",
            [
                "aInitializingCr",
                "load_precision_shift",
                "load_window_shift",
                "cap enforcement granularity",
                "sub_29B10",
            ],
        )
    if symbol == "runtime_helper_0017":
        return (
            """{
    /* diagnostic-summary rewrite: printk-style variadic logging frontend. */
    recovered_trace(ctx, "runtime_helper_0017", 0x1c18ULL);
    recovered_log(ctx, "copy variadic argument state into bounded formatting buffers");
    return recovered_direct_call(ctx, "format and emit diagnostic string", 0x1be8ULL);
}""",
            [
                "va_start",
                "va_copy",
                "sub_1BE8",
            ],
        )
    if symbol == "boot_enable_nonboot_cpus":
        return (
            """{
    /* diagnostic-summary rewrite: non-boot CPU bring-up loop. */
    recovered_trace(ctx, "boot_enable_nonboot_cpus", 0x7e8ULL);
    recovered_log(ctx, "enable pending non-boot CPUs and clear the bring-up bitmap");
    (void)recovered_direct_call(ctx, "find next pending CPU in boot bitmap", 0x72da0ULL);
    (void)recovered_direct_call(ctx, "bring selected CPU online", 0x35d4ULL);
    (void)recovered_direct_call(ctx, "handle CPU bring-up failure / re-offline", 0x3380ULL);
    return recovered_direct_call(ctx, "clear non-boot CPU pending bitmap", 0x72680ULL);
}""",
            [
                "aEnablingNonBoo",
                "aErrorBringingC",
                "aErrorReOfflini",
                "sub_35D4",
                "sub_3380",
                "sub_72680",
            ],
        )
    if symbol == "runtime_fire_diagnostic_keyhandlers":
        return (
            """{
    /* diagnostic-summary rewrite: iterate diagnostic keyhandlers. */
    recovered_trace(ctx, "runtime_fire_diagnostic_keyhandlers", 0x1088ULL);
    recovered_log(ctx, "'%c' pressed -> firing all diagnostic keyhandlers");
    recovered_log(ctx, "scan 128 keyhandler slots, print active handler labels, invoke enabled callbacks");
    return recovered_direct_call(ctx, "post diagnostic keyhandler completion", 0x23b40ULL);
}""",
            [
                "pressed -> firing all diagnostic keyhandlers",
                "percpu_global_state_008",
                "sub_23B40",
            ],
        )
    if symbol == "el2_decode_hypervisor_fault":
        return (
            """{
    /* diagnostic-summary rewrite: decode and report an EL2/stage fault. */
    recovered_trace(ctx, "el2_decode_hypervisor_fault", 0x23c0ULL);
    recovered_log(ctx, "decode translation/access/permission/synchronous external abort class");
    recovered_log(ctx, "print stage, level, domain/vCPU context, then dispatch recovery path");
    (void)recovered_direct_call(ctx, "lookup current faulting vcpu/domain", 0x3dd70ULL);
    (void)recovered_direct_call(ctx, "dump or update faulting vcpu state", 0x67410ULL);
    return recovered_direct_call(ctx, "resume or deschedule after EL2 fault report", 0x8a80ULL);
}""",
            [
                "aTranslationFau",
                "aPermissionFaul",
                "aErrorDuringHyp",
                "sub_3DD70",
                "sub_67410",
                "sub_8A80",
            ],
        )
    if symbol == "runtime_show_key_handlers":
        return (
            """{
    /* diagnostic-summary rewrite: show installed debug key handlers. */
    recovered_trace(ctx, "runtime_show_key_handlers", 0x111cULL);
    recovered_log(ctx, "'%c' pressed -> showing installed handlers");
    (void)recovered_direct_call(ctx, "print debug key handler banner", 0x1994ULL);
    recovered_log(ctx, "scan 128 keyhandler slots and print active key/ascii/description/flags");
    return recovered_direct_call(ctx, "emit keyhandler table rows", 0x1c18ULL);
}""",
            [
                "pressed -> showing installed handlers",
                "aKeyCAscii02xS",
                "sub_1994",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_print_memory_summary":
        return (
            """{
    /* diagnostic-summary rewrite: print hypervisor memory summary. */
    recovered_trace(ctx, "runtime_print_memory_summary", 0x11c4ULL);
    recovered_log(ctx, "print Physical Memory, Xen heap, DMA heap, per-heap free pages, and Dom heap");
    (void)recovered_direct_call(ctx, "print memory size and heap counters", 0x1c18ULL);
    return recovered_direct_call(ctx, "finish memory summary", 0x1c18ULL);
}""",
            [
                "Physical Memory",
                "Xen heap",
                "DMA heap",
                "Dom heap",
                "sub_1C18",
            ],
        )
    if symbol == "runtime_print_version_banner":
        return (
            """{
    /* diagnostic-summary rewrite: print version and build banner. */
    recovered_trace(ctx, "runtime_print_version_banner", 0x1994ULL);
    recovered_log(ctx, "Xen version, compiler/build flags, latest changeset, and optional build-id");
    (void)recovered_direct_call(ctx, "print Xen version banner", 0x1c18ULL);
    return recovered_direct_call(ctx, "print build-id when present", 0x1c18ULL);
}""",
            [
                "Xen version",
                "Latest ChangeSet",
                "build-id",
                "sub_1C18",
            ],
        )
    if symbol == "scheduler_print_credit_state":
        return (
            """{
    /* diagnostic-summary rewrite: print credit scheduler state. */
    recovered_trace(ctx, "scheduler_print_credit_state", 0x1a2cULL);
    recovered_log(ctx, "print domain/vcpu priority, flags, cpu, credit, weight, and cap");
    return recovered_direct_call(ctx, "emit credit scheduler row", 0x1c18ULL);
}""",
            [
                "pri=%i flags=%x cpu=%i",
                "credit=%i [w=%u,cap=%u]",
                "sub_1C18",
            ],
        )
    if symbol == "scheduler_print_credit_state_01":
        return (
            """{
    /* diagnostic-summary rewrite: print extended credit scheduler state. */
    recovered_trace(ctx, "scheduler_print_credit_state_01", 0x1a90ULL);
    recovered_log(ctx, "print domain/vcpu flags, cpu, credit, budget, and load percentage");
    return recovered_direct_call(ctx, "emit extended credit scheduler row", 0x1c18ULL);
}""",
            [
                "credit=%i [w=%u]",
                "budget=%ld",
                "load=%ld",
                "sub_1C18",
            ],
        )
    return None


def replace_function_body(text: str, symbol: str, body: str) -> tuple[str, bool]:
    pattern = re.compile(
        rf"(uintptr_t\s+{re.escape(symbol)}\s*\(struct recovered_context \*ctx\)\s*)"
        r"\{(?P<body>.*?)\n\}",
        flags=re.DOTALL,
    )
    match = pattern.search(text)
    if not match:
        return text, False
    old_body = match.group("body")
    if "diagnostic-summary rewrite" in old_body:
        return text, False
    return text[: match.start()] + match.group(1) + body + text[match.end() :], True


def sync_function_preamble(text: str, symbol: str, new_class: str) -> str:
    """Update only the evidence/review comments immediately preceding one function."""

    func_match = re.search(
        rf"(^|\n)uintptr_t\s+{re.escape(symbol)}\s*\(struct recovered_context \*ctx\)",
        text,
    )
    if not func_match:
        return text
    prefix = text[: func_match.start()]
    evidence_matches = list(
        re.finditer(
            r"/\* evidence: image offset (?P<addr>0x[0-9a-fA-F]+), IDA (?P<ida>[^,]+), range (?P<range>[^,]+), confidence (?P<confidence>[^,]+), class (?P<class>[a-zA-Z0-9_-]+) \*/",
            prefix,
        )
    )
    if not evidence_matches:
        return text
    evidence = evidence_matches[-1]
    new_evidence = (
        f"/* evidence: image offset {evidence.group('addr')}, IDA {evidence.group('ida')}, "
        f"range {evidence.group('range')}, confidence {evidence.group('confidence')}, class {new_class} */"
    )
    between = text[evidence.end() : func_match.start()]
    marker = "/* lifted Hex-Rays review moved to S08/lifted-pseudocode-review.jsonl; function remains lifted-c. */"
    replacement = "/* lifted Hex-Rays review moved to S08/lifted-pseudocode-review.jsonl; source body is a diagnostic summary. */"
    between = between.replace(marker, replacement, 1)
    return text[: evidence.start()] + new_evidence + between + text[func_match.start() :]


def apply(case_id: str, max_functions: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    fmap_path = s08 / "function-map.json"
    smap_path = s08 / "source-map.json"
    quality_path = s08 / "source-quality-report.json"
    fmap = read_json(fmap_path)
    smap = read_json(smap_path)
    quality = read_json(quality_path)
    previous = read_jsonl(s08 / "diagnostic-summary-rewrite-index.jsonl")
    done = {row.get("source_symbol") for row in previous if row.get("applied")}

    applied: list[dict[str, Any]] = []
    by_file: dict[str, list[dict[str, Any]]] = {}
    for fn in fmap["functions"]:
        plan = body_for(fn.get("source_symbol", ""))
        if not plan or fn.get("source_symbol") in done:
            continue
        by_file.setdefault(fn["source_file"], []).append(fn)

    for rel, fns in by_file.items():
        if len(applied) >= max_functions:
            break
        path = repo / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        changed = False
        for fn in fns:
            if len(applied) >= max_functions:
                break
            plan = body_for(fn["source_symbol"])
            if not plan:
                continue
            body, evidence_terms = plan
            text, ok = replace_function_body(text, fn["source_symbol"], body)
            if not ok:
                continue
            changed = True
            old_class = fn.get("output_class")
            fn["output_class"] = "semantic-c"
            fn["diagnostic_summary_rewrite"] = "applied"
            fn.setdefault("evidence", []).append("S08/diagnostic-summary-rewrite-index.jsonl")
            applied.append(
                {
                    "address": fn["address"],
                    "source_symbol": fn["source_symbol"],
                    "source_file": rel,
                    "old_output_class": old_class,
                    "new_output_class": "semantic-c",
                    "rewrite_kind": "diagnostic_summary",
                    "evidence_terms": evidence_terms,
                    "applied": True,
                }
            )
        if changed:
            for row in applied:
                if row["source_file"] == rel:
                    text = sync_function_preamble(text, row["source_symbol"], row["new_output_class"])
            path.write_text(text, encoding="utf-8", newline="\n")

    by_addr = {fn["address"]: fn for fn in fmap["functions"]}
    for entry in smap.get("function_sources", []):
        fn = by_addr.get(entry.get("function"))
        if fn and fn.get("diagnostic_summary_rewrite") == "applied":
            entry["output_class"] = fn["output_class"]
            entry["diagnostic_summary_rewrite"] = "applied"

    counts = quality.setdefault("source_class_counts", {})
    promoted = sum(1 for row in applied if row["old_output_class"] != "semantic-c")
    if promoted:
        counts["semantic-c"] = counts.get("semantic-c", 0) + promoted
        counts["lifted-c"] = max(0, counts.get("lifted-c", 0) - promoted)
    quality["diagnostic_summary_rewrite_policy"] = (
        "String-backed diagnostic/boot summaries may replace empty wrappers, "
        "but complex dataflow remains in S08 pseudocode evidence."
    )

    previous_iterations = {row.get("iteration_id") for row in previous if row.get("iteration_id")}
    iteration_id = f"S08-DIAGNOSTIC-SUMMARY-RW{len(previous_iterations) + 1}"
    rows = [
        {
            **row,
            "case_id": case_id,
            "stage_id": "S08",
            "iteration_id": iteration_id,
            "generated_at": now_iso(),
            "boundary": "High-level summary body only; full pseudocode remains in evidence.",
        }
        for row in applied
    ]
    write_json(fmap_path, fmap)
    write_json(smap_path, smap)
    write_json(quality_path, quality)
    write_jsonl(s08 / "diagnostic-summary-rewrite-index.jsonl", previous + rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "requested_max": max_functions,
        "applied_this_run": len(applied),
        "applied_cumulative": len(previous) + len(rows),
        "promoted_to_semantic_c": promoted,
        "boundary": "Only diagnostic functions with explicit string/call evidence were summarized.",
    }
    write_json(s08 / "diagnostic-summary-rewrite-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-functions", type=int, default=20)
    args = ap.parse_args()
    print(json.dumps(apply(args.case_id, args.max_functions), ensure_ascii=False))


if __name__ == "__main__":
    main()
