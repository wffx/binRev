#!/usr/bin/env python3
"""Apply semantic names from architecture/string evidence.

Unlike apply_semantic_names.py, this pass can rename functions whose bodies are
still lifted-c when strong S04/S07 evidence exists (sysregs, GIC/timer/SMMU
strings, exception/fault registers, TPIDR_EL2 neighborhoods). It does not
promote output_class; it only improves source naming.
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
GENERIC_RE = re.compile(
    r"^(?:(?:runtime_helper|boot_helper|cache_helper|mmu_helper|mmu_switch_or_enable|percpu_access|timer_event|timer_control|interrupt_helper|interrupt_route|exception_helper|stage2_helper|unknown_helper)_\d{4}|(?:runtime_access_current_cpu_state|percpu_access_current_cpu_state|arm64_cache_tlb_maintenance)(?:_\d+)?|nullsub_\d+)$"
)


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


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_events(path: Path) -> dict[str, dict[str, set[str]]]:
    by_function: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"tokens": set(), "lines": set()})
    if not path.exists():
        return by_function
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        fn = row.get("function")
        if not fn:
            continue
        if row.get("token"):
            by_function[fn]["tokens"].add(row["token"])
        if row.get("line"):
            by_function[fn]["lines"].add(row["line"])
    return by_function


def load_decompile(path: Path) -> dict[str, str]:
    doc = read_json(path)
    out: dict[str, str] = {}
    for fn in doc.get("functions", []):
        lines = fn.get("pseudocode", {}).get("lines", [])
        disasm = [item.get("text", "") for item in fn.get("disasm", [])]
        out[fn["address"]] = "\n".join(lines + disasm)
    return out


def load_external_pseudocode(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in read_jsonl(path):
        if row.get("address") and row.get("pseudocode"):
            out[row["address"]] = row["pseudocode"]
    return out


def classify_name(fn: dict[str, Any], evidence: str, tokens: set[str]) -> tuple[str, str] | None:
    module = fn.get("module", "")
    source_file = fn.get("source_file", "")
    text = evidence

    if str(fn.get("ida_name", "")).startswith("nullsub_"):
        return "recovered_empty_callback", "IDA nullsub empty-function evidence"

    if "VBAR_EL2" in text:
        return "install_el2_exception_vectors", "VBAR_EL2"
    if any(reg in text for reg in ["ESR_EL2", "FAR_EL2", "HPFAR_EL2"]):
        return "decode_el2_fault_context", "ESR/FAR/HPFAR_EL2"
    if "CurrentEL" in text:
        return "check_current_exception_level", "CurrentEL"
    if "MPIDR_EL1" in text:
        return "read_mpidr_cpu_identity", "MPIDR_EL1"

    if source_file.endswith("runtime.c") or module == "runtime":
        if "pressed -> firing all diagnostic keyhandlers" in text:
            return "runtime_fire_diagnostic_keyhandlers", "diagnostic keyhandler string"
        if "pressed -> dumping event-channel info" in text or "Event Channel" in text or "aEventChannelIn" in text:
            return "runtime_dump_event_channel_info", "event-channel diagnostic string"
        if "gnttab usage" in text or "grant-table for remote" in text or "aGnttabUsagePri" in text:
            return "runtime_dump_grant_table_usage", "grant-table diagnostic string"
        if "rebooting machine" in text or "noreboot" in text:
            return "runtime_request_machine_reboot", "reboot diagnostic string"
        if "Xen version" in text or "Latest ChangeSet" in text or "build-id" in text:
            return "runtime_print_version_banner", "version banner strings"
        if "showing installed handlers" in text:
            return "runtime_show_key_handlers", "key-handler diagnostic string"
        if "Physical Memory" in text or "Xen heap" in text:
            return "runtime_print_memory_summary", "memory summary strings"
        if "credit=" in text or "budget=" in text or "load=" in text:
            return "scheduler_print_credit_state", "scheduler credit diagnostic strings"
        if "pressed ->" in text:
            return "runtime_handle_debug_key", "debug-key diagnostic strings"
        if "PIRQ" in text or "aPDID" in text:
            return "runtime_print_irq_mapping_state", "IRQ mapping diagnostic evidence"
        if "WARNING" in text:
            return "runtime_emit_warning", "warning string evidence"

    if "Enabling non-boot" in text or "aEnablingNonBoo" in text or "aErrorBringingC" in text or "aErrorReOfflini" in text:
        return "boot_enable_nonboot_cpus", "non-boot CPU bring-up strings"
    if "firing all diagnostic keyhandlers" in text:
        return "runtime_fire_diagnostic_keyhandlers", "diagnostic keyhandler string"
    if any(s in text for s in ["aTranslationFau", "aPermissionFaul", "aAccessFault", "aErrorDuringHyp", "Translation fault", "Permission fault"]):
        return "el2_decode_hypervisor_fault", "EL2 fault diagnostic strings"
    if "GICH_LRs" in text:
        return "vgic_dump_list_register_state", "GICH_LRs diagnostic string"

    if source_file.endswith("interrupt.c") or module == "interrupt":
        if "Bad mode" in text or "aBadMode" in text:
            return "interrupt_handle_bad_mode_exception", "bad-mode/ESR exception evidence"
        if "GICv2" in text and ("v2m" in text or "V2M" in text):
            return "gicv2_configure_v2m_msi_frame", "GICv2/v2m strings"
        if "GICv3" in text:
            return "gicv3_configure_interrupt_controller", "GICv3 strings"
        if "MSI" in text:
            return "gic_configure_msi_interrupts", "MSI strings"
        if "EOI" in text or "deactivate" in text:
            return "gic_complete_interrupt", "GIC EOI/deactivate strings"
        if "IRQ" in text or "interrupt" in text:
            return "gic_route_or_inject_interrupt", "interrupt/IRQ strings"

    if "GICv2: Mapping v2m" in text or "aGicv2MappingV2" in text:
        return "gicv2_map_v2m_frame", "GICv2 v2m mapping string"
    if "GICv2: Creating v2m" in text or "aGicv2CreatingV" in text or "v2m DT node" in text:
        return "gicv2_create_v2m_dt_node", "GICv2 v2m DT strings"
    if "Failed to set v2m MSI" in text or "Failed to route v2m MSI" in text or "reserve v2m MSI" in text:
        return "gicv2_configure_v2m_msi_frame", "GICv2 v2m MSI strings"
    if "timer IRQ" in text and "level triggered" in text:
        return "timer_validate_irq_trigger_mode", "timer IRQ trigger diagnostic string"

    if any(reg in text for reg in ["VTCR_EL2", "VTTBR_EL2"]):
        if "HCR_EL2" in text:
            return "stage2_enable_vm_translation", "VTCR/VTTBR/HCR_EL2"
        return "stage2_update_vttbr_context", "VTCR/VTTBR_EL2"
    if "HCR_EL2" in text:
        if "ICH_HCR_EL2" in text:
            return "vgic_update_hcr_state", "ICH_HCR_EL2"
        return "el2_update_hcr_state", "HCR_EL2"
    if any(reg in text for reg in ["TTBR0_EL2", "SCTLR_EL2", "TCR_EL2", "MAIR_EL2"]):
        return "el2_mmu_update_translation_state", "EL2 MMU sysregs"
    if "TLBI" in text or "IC              " in text or "DC              " in text:
        return None

    if any(reg in text for reg in ["CNTHP_CTL_EL2", "CNTP_CTL_EL0", "CNTVOFF_EL2", "CNTHCTL_EL2"]):
        if "CNTVOFF_EL2" in text:
            return "timer_configure_virtual_offset", "CNTVOFF_EL2"
        return "timer_configure_el2_timer", "CNTHP/CNTP/CNTHCTL"
    if source_file.endswith("timer.c") or module == "timer":
        if "deadline" in text or "expires" in text:
            return "timer_update_deadline", "timer deadline strings"
        if "timeout" in text:
            return "timer_handle_timeout", "timer timeout strings"
        if "interrupt" in text or "IRQ" in text:
            return "timer_configure_interrupt", "timer interrupt strings"
        if "counter" in text or "CNT" in text:
            return "timer_read_or_program_counter", "timer counter strings"

    if any(reg in text for reg in ["ICC_IAR1_EL1", "ICC_EOIR1_EL1", "ICC_DIR_EL1"]):
        if "ICC_IAR1_EL1" in text:
            return "gic_read_interrupt_acknowledge", "ICC_IAR1_EL1"
        return "gic_end_or_deactivate_interrupt", "ICC_EOIR1/ICC_DIR"
    if "ICH_LR" in text:
        if re.search(r"MSR\s+ICH_LR", text):
            return "vgic_write_list_register", "ICH_LR write"
        return "vgic_read_list_register", "ICH_LR read"
    if any(reg in text for reg in ["ICH_VMCR_EL2", "ICC_SRE_EL", "ICH_AP"]):
        return "vgic_configure_system_registers", "ICH/ICC virtual interface"
    if "GICv2" in text and "v2m" in text:
        return "gicv2_configure_v2m_msi_frame", "GICv2/v2m strings"
    if "GICv3" in text:
        return "gicv3_initialize_controller", "GICv3 strings"
    if "vGICD" in text:
        return "vgicd_handle_mmio_access", "vGICD strings"
    if "vGICR" in text:
        return "vgicr_handle_mmio_access", "vGICR strings"

    if "SMMU" in text or "smmu:" in text:
        if "TLB sync" in text:
            return "smmu_wait_for_tlb_sync", "SMMU TLB sync string"
        if "stream ID" in text:
            return "smmu_validate_stream_id", "SMMU stream ID string"
        return "smmu_configure_device_context", "SMMU strings"

    if "TPIDR_EL2" in text:
        return None

    if "DAIFSet" in text or "DAIFClr" in text:
        return "arm64_update_interrupt_mask", "DAIF"

    return None


def unique_name(base: str, used: set[str], counters: dict[str, int]) -> str:
    if base not in used:
        used.add(base)
        return base
    counters[base] += 1
    while True:
        candidate = f"{base}_{counters[base]:02d}"
        if candidate not in used:
            used.add(candidate)
            return candidate
        counters[base] += 1


def replace_symbols(repo: Path, renames: dict[str, str]) -> dict[str, int]:
    counts = {old: 0 for old in renames}
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.suffix not in {".c", ".h", ".S"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for old, new in sorted(renames.items(), key=lambda item: len(item[0]), reverse=True):
            text, n = re.subn(rf"\b{re.escape(old)}\b", new, text)
            counts[old] += n
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")
    return counts


def repair_evidence_comments(repo: Path, functions: list[dict[str, Any]]) -> None:
    by_file: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for fn in functions:
        by_file[fn["source_file"]].append(fn)
    for rel, rows in by_file.items():
        path = repo / rel
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        original = text
        for fn in rows:
            addr = re.escape(fn["address"].lower())
            ida_name = fn["ida_name"]
            text = re.sub(
                rf"(/\* evidence: image offset {addr}, IDA )[^,]+(, range )",
                rf"\g<1>{ida_name}\g<2>",
                text,
                flags=re.IGNORECASE,
            )
            text = re.sub(
                rf"(/\* evidence: original IDA name )[^,]+(, image offset {addr} \*/)",
                rf"\g<1>{ida_name}\g<2>",
                text,
                flags=re.IGNORECASE,
            )
        if text != original:
            path.write_text(text, encoding="utf-8", newline="\n")


def apply_names(case_id: str, max_renames: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s04 = case / "stages" / "S04"
    s07 = case / "stages" / "S07"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"

    function_map_path = s08 / "function-map.json"
    source_map_path = s08 / "source-map.json"
    function_map_doc = read_json(function_map_path)
    source_map_doc = read_json(source_map_path)
    functions = function_map_doc["functions"]
    events = load_events(s04 / "architecture-events.jsonl")
    decompile = load_decompile(s07 / "decompile-export-full.json")
    external_pseudocode = load_external_pseudocode(s08 / "lifted-pseudocode-review.jsonl")

    used = {fn["source_symbol"] for fn in functions}
    counters: dict[str, int] = defaultdict(int)
    plan: list[dict[str, Any]] = []
    for fn in functions:
        old = fn.get("source_symbol", "")
        if not GENERIC_RE.fullmatch(old):
            continue
        ev = events.get(fn["address"], {"tokens": set(), "lines": set()})
        evidence_text = (
            decompile.get(fn["address"], "")
            + "\n"
            + external_pseudocode.get(fn["address"], "")
            + "\n"
            + "\n".join(sorted(ev["lines"]))
        )
        classified = classify_name(fn, evidence_text, ev["tokens"])
        if not classified:
            continue
        base, reason = classified
        new = unique_name(base, used, counters)
        plan.append(
            {
                "address": fn["address"],
                "old_symbol": old,
                "new_symbol": new,
                "source_file": fn["source_file"],
                "module": fn.get("module"),
                "reason": reason,
                "output_class": fn.get("output_class"),
            }
        )
        if len(plan) >= max_renames:
            break

    renames = {row["old_symbol"]: row["new_symbol"] for row in plan}
    counts = replace_symbols(repo, renames)
    by_addr = {fn["address"]: fn for fn in functions}
    for row in plan:
        fn = by_addr[row["address"]]
        fn["source_symbol"] = row["new_symbol"]
        fn["semantic_name"] = row["new_symbol"]
        fn.setdefault("evidence", []).append("S08/evidence-semantic-name-index.jsonl")
        row["occurrences_replaced"] = counts.get(row["old_symbol"], 0)

    for entry in source_map_doc.get("function_sources", []):
        symbol = entry.get("source_symbol") or entry.get("symbol")
        if symbol in renames:
            if "source_symbol" in entry:
                entry["source_symbol"] = renames[symbol]
            if "symbol" in entry:
                entry["symbol"] = renames[symbol]
            entry["semantic_name"] = renames[symbol]

    repair_evidence_comments(repo, functions)

    index_path = s08 / "evidence-semantic-name-index.jsonl"
    previous_rows = read_jsonl(index_path)
    iteration_id = f"S08-EVIDENCE-NAME-RW{len({row.get('iteration_id') for row in previous_rows if row.get('iteration_id')}) + 1}"

    function_map_doc["evidence_semantic_name_iteration"] = iteration_id
    source_map_doc["evidence_semantic_name_iteration"] = iteration_id
    write_json(function_map_path, function_map_doc)
    write_json(source_map_path, source_map_doc)

    new_rows = [
        {**row, "case_id": case_id, "stage_id": "S08", "iteration_id": iteration_id, "generated_at": now_iso()}
        for row in plan
    ]
    write_jsonl(index_path, previous_rows + new_rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": iteration_id,
        "requested_max": max_renames,
        "renamed_this_run": len(plan),
        "total_renamed": len(previous_rows) + len(new_rows),
        "occurrences_replaced_this_run": sum(row.get("occurrences_replaced", 0) for row in plan),
        "total_occurrences_replaced": sum(row.get("occurrences_replaced", 0) for row in previous_rows + new_rows),
        "boundary": "Only generic source symbols with strong architecture/string evidence were renamed; output_class was not promoted.",
    }
    write_json(s08 / "evidence-semantic-name-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-renames", type=int, default=300)
    args = ap.parse_args()
    print(json.dumps(apply_names(args.case_id, args.max_renames), ensure_ascii=False))


if __name__ == "__main__":
    main()
