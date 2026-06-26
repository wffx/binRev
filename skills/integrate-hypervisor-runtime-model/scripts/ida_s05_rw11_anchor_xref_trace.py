"""IDA-side S05-RW11 anchor xref/write trace.

Run inside IDA with IDAPython. It traces:

- dominant global anchors such as dword_96000
- TPIDR-heavy candidate functions from S05-RW10

The script is read-only: it does not rename, comment, type, patch, or create
functions. It writes a JSON artifact for later integration.
"""

from __future__ import annotations

import json
import os
import re

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_ua
import idautils
import idc


ROOT = os.environ.get("BINREV_ROOT", r"F:\AI\codexProject\binRev")
OUT = os.environ.get(
    "BINREV_S05_RW11_OUT",
    os.path.join(ROOT, "cases", "xen_arm64-778090a1", "stages", "S05", "s05-rw11-anchor-xref-trace.json"),
)
GLOBAL_NAMES = [s for s in os.environ.get("BINREV_S05_RW11_GLOBALS", "dword_96000").split(",") if s]
TPIDR_FUNCS = [s for s in os.environ.get("BINREV_S05_RW11_TPIDR_FUNCS", "0x13144,0x18ee0,0x12360,0x468d0,0x68254").split(",") if s]


def hx(ea):
    return None if ea is None or ea == idc.BADADDR else hex(int(ea))


def dis(ea):
    try:
        return idc.generate_disasm_line(ea, 0) or ""
    except Exception:
        return ""


def func_at(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return {
        "start": hx(f.start_ea),
        "end": hx(f.end_ea),
        "name": ida_funcs.get_func_name(f.start_ea),
    }


def classify_insn(text):
    t = text.upper()
    if t.startswith("STR") or t.startswith("STP") or t.startswith("STUR"):
        return "write"
    if t.startswith("LDR") or t.startswith("LDP") or t.startswith("LDUR"):
        return "read"
    if t.startswith("ADR") or t.startswith("ADRP") or "PAGE" in t:
        return "address_calc"
    if t.startswith("ADD") or t.startswith("SUB") or t.startswith("MOV"):
        return "compute"
    return "other"


def trace_global(name):
    ea = ida_name.get_name_ea(idc.BADADDR, name)
    rec = {
        "name": name,
        "ea": hx(ea),
        "exists": ea != idc.BADADDR,
        "xrefs": [],
        "read_count": 0,
        "write_count": 0,
        "address_calc_count": 0,
        "other_count": 0,
        "functions": {},
        "decision": "unresolved",
    }
    if ea == idc.BADADDR:
        rec["decision"] = "missing_name"
        return rec

    for xr in idautils.XrefsTo(ea, 0):
        frm = xr.frm
        text = dis(frm)
        kind = classify_insn(text)
        rec[kind + "_count"] = rec.get(kind + "_count", 0) + 1
        f = func_at(frm)
        if f:
            rec["functions"].setdefault(f["start"], f)
        rec["xrefs"].append(
            {
                "from": hx(frm),
                "type": str(xr.type),
                "kind": kind,
                "text": text,
                "function": f,
            }
        )
    if rec["write_count"]:
        rec["decision"] = "global_state_candidate_with_writes"
    elif rec["read_count"] or rec["address_calc_count"]:
        rec["decision"] = "global_read_or_constant_candidate"
    else:
        rec["decision"] = "global_anchor_without_xrefs"
    rec["functions"] = list(rec["functions"].values())
    return rec


def iter_func_items(start):
    f = ida_funcs.get_func(start)
    if not f:
        return []
    return list(idautils.FuncItems(f.start_ea))


def trace_tpidr_func(addr_s):
    start = int(addr_s, 16)
    f = ida_funcs.get_func(start)
    rec = {
        "function": func_at(start),
        "requested_start": addr_s,
        "exists": bool(f),
        "tpidr_reads": [],
        "offset_uses": [],
        "memory_use_count": 0,
        "write_like_count": 0,
        "read_like_count": 0,
        "decision": "missing_function",
    }
    if not f:
        return rec

    last_tpidr_reg = None
    for ea in iter_func_items(start):
        text = dis(ea)
        upper = text.upper()
        if "TPIDR_EL2" in upper and "MRS" in upper:
            m = re.search(r"MRS\s+(X\d+|W\d+)", upper)
            last_tpidr_reg = m.group(1) if m else None
            rec["tpidr_reads"].append({"ea": hx(ea), "text": text, "dest_reg": last_tpidr_reg})
            continue
        if last_tpidr_reg and last_tpidr_reg in upper:
            kind = classify_insn(text)
            # Operand-value APIs vary across IDA builds; keep disassembly text as primary evidence.
            is_mem = "[" in text and "]" in text
            if is_mem:
                rec["memory_use_count"] += 1
                if kind == "write":
                    rec["write_like_count"] += 1
                if kind == "read":
                    rec["read_like_count"] += 1
                rec["offset_uses"].append({"ea": hx(ea), "kind": kind, "text": text})
    if rec["write_like_count"]:
        rec["decision"] = "tpidr_offset_family_has_writes_review_only"
    elif rec["memory_use_count"]:
        rec["decision"] = "tpidr_offset_family_read_only_review_only"
    else:
        rec["decision"] = "tpidr_reads_without_local_memory_use"
    return rec


def main():
    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw11_anchor_xref_trace.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW11",
        "policy": "read_only_ida_trace",
        "global_anchors": [trace_global(name) for name in GLOBAL_NAMES],
        "tpidr_functions": [trace_tpidr_func(addr) for addr in TPIDR_FUNCS],
        "summary": {},
        "decision": {
            "status": "review_required_ida_anchor_xref_trace",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "IDA xref/write traces are evidence seeds only; ownership requires lifetime/resource identity closure.",
        },
    }
    result["summary"] = {
        "global_anchor_count": len(result["global_anchors"]),
        "global_with_writes": sum(1 for r in result["global_anchors"] if r.get("write_count", 0) > 0),
        "tpidr_function_count": len(result["tpidr_functions"]),
        "tpidr_with_write_like_uses": sum(1 for r in result["tpidr_functions"] if r.get("write_like_count", 0) > 0),
        "production_ownership_ready_count": 0,
    }
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW11 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
