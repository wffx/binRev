"""IDA-side S05-RW12 writer-to-lifetime closure trace.

This read-only IDAPython script consumes S05-RW11 output and deepens it:

- traces the unique global writer function for dword_96000
- summarizes callers/callees/sysregs/strings around writer and TPIDR functions
- checks direct call overlap between the global writer and TPIDR-heavy functions
- emits review-only closure evidence; it never mutates IDA
"""

from __future__ import annotations

import json
import os
import re

import ida_funcs
import ida_kernwin
import idautils
import idc


ROOT = os.environ.get("BINREV_ROOT", r"F:\AI\codexProject\binRev")
S05 = os.path.join(ROOT, "cases", "xen_arm64-778090a1", "stages", "S05")
RW11 = os.environ.get("BINREV_S05_RW11", os.path.join(S05, "s05-rw11-anchor-xref-trace.json"))
OUT = os.environ.get("BINREV_S05_RW12_OUT", os.path.join(S05, "s05-rw12-writer-lifetime-closure.json"))

SYSREG_PATTERNS = [
    "TPIDR_EL2",
    "VTTBR_EL2",
    "VTCR_EL2",
    "HCR_EL2",
    "MPIDR_EL1",
    "SCTLR_EL2",
    "TCR_EL2",
    "TTBR0_EL2",
    "VBAR_EL2",
    "ESR_EL2",
    "FAR_EL2",
    "HPFAR_EL2",
    "ICH_",
]


def hx(ea):
    return None if ea is None or ea == idc.BADADDR else hex(int(ea))


def parse_hex(s):
    if not s:
        return None
    try:
        return int(str(s), 16)
    except Exception:
        return None


def dis(ea):
    return idc.generate_disasm_line(ea, 0) or ""


def func_at(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return {
        "start": hx(f.start_ea),
        "end": hx(f.end_ea),
        "name": ida_funcs.get_func_name(f.start_ea),
        "size": int(f.end_ea - f.start_ea),
    }


def func_by_start(start_s):
    start = parse_hex(start_s)
    return ida_funcs.get_func(start) if start is not None else None


def collect_callers(start_ea, limit=80):
    callers = {}
    for xr in idautils.CodeRefsTo(start_ea, 0):
        f = ida_funcs.get_func(xr)
        if f:
            callers[hx(f.start_ea)] = {
                "callsite": hx(xr),
                "function": func_at(f.start_ea),
                "text": dis(xr),
            }
        if len(callers) >= limit:
            break
    return list(callers.values())


def collect_callees(f, limit=120):
    out = []
    seen = set()
    if not f:
        return out
    for ea in idautils.FuncItems(f.start_ea):
        for to in idautils.CodeRefsFrom(ea, 0):
            tf = ida_funcs.get_func(to)
            if not tf:
                continue
            key = (ea, tf.start_ea)
            if key in seen:
                continue
            seen.add(key)
            out.append({"callsite": hx(ea), "target": func_at(tf.start_ea), "text": dis(ea)})
            if len(out) >= limit:
                return out
    return out


def collect_strings(f, limit=40):
    out = []
    if not f:
        return out
    try:
        strings = list(idautils.Strings())
    except Exception:
        strings = []
    string_addrs = {int(s.ea): str(s) for s in strings}
    for ea in idautils.FuncItems(f.start_ea):
        for dr in idautils.DataRefsFrom(ea):
            if dr in string_addrs:
                out.append({"from": hx(ea), "string_ea": hx(dr), "text": string_addrs[dr]})
                if len(out) >= limit:
                    return out
    return out


def collect_sysregs(f):
    counts = {}
    samples = []
    if not f:
        return {"counts": counts, "samples": samples}
    for ea in idautils.FuncItems(f.start_ea):
        text = dis(ea)
        upper = text.upper()
        for pat in SYSREG_PATTERNS:
            if pat in upper:
                counts[pat] = counts.get(pat, 0) + 1
                if len(samples) < 80:
                    samples.append({"ea": hx(ea), "pattern": pat, "text": text})
    return {"counts": counts, "samples": samples}


def disasm_window(ea_s, before=12, after=16):
    ea = parse_hex(ea_s)
    if ea is None:
        return []
    # Simple fixed-size ARM64-ish window; IDA item stepping is not required for evidence.
    start = max(0, ea - before * 4)
    out = []
    for cur in range(start, ea + (after + 1) * 4, 4):
        out.append({"ea": hx(cur), "text": dis(cur), "is_focus": cur == ea})
    return out


def summarize_function(start_s, focus_ea=None):
    f = func_by_start(start_s)
    start = parse_hex(start_s)
    return {
        "function": func_at(start) if start is not None else None,
        "exists": bool(f),
        "caller_count": len(collect_callers(f.start_ea)) if f else 0,
        "callers": collect_callers(f.start_ea, limit=40) if f else [],
        "callee_count": len(collect_callees(f)) if f else 0,
        "callees": collect_callees(f, limit=80) if f else [],
        "sysregs": collect_sysregs(f) if f else {"counts": {}, "samples": []},
        "strings": collect_strings(f, limit=30) if f else [],
        "focus_window": disasm_window(focus_ea) if focus_ea else [],
    }


def main():
    with open(RW11, "r", encoding="utf-8") as fp:
        rw11 = json.load(fp)

    global_anchor = rw11.get("global_anchors", [{}])[0]
    write_xrefs = [x for x in global_anchor.get("xrefs", []) if x.get("kind") == "write"]
    writer_func_starts = sorted({x.get("function", {}).get("start") for x in write_xrefs if x.get("function")})
    writer_focus = {x.get("function", {}).get("start"): x.get("from") for x in write_xrefs if x.get("function")}

    tpidr_starts = [r.get("function", {}).get("start") or r.get("requested_start") for r in rw11.get("tpidr_functions", [])]
    tpidr_starts = [s for s in tpidr_starts if s]

    writer_summaries = []
    for s in writer_func_starts:
        item = summarize_function(s, writer_focus.get(s))
        # Check direct calls from writer to TPIDR-heavy functions.
        callees = {c.get("target", {}).get("start") for c in item.get("callees", [])}
        item["direct_tpidr_callee_overlap"] = sorted(callees.intersection(set(tpidr_starts)))
        writer_summaries.append(item)

    tpidr_summaries = []
    for s in tpidr_starts:
        item = summarize_function(s)
        callers = {c.get("function", {}).get("start") for c in item.get("callers", [])}
        item["called_by_global_writer"] = sorted(callers.intersection(set(writer_func_starts)))
        tpidr_summaries.append(item)

    writer_reaches_tpidr = any(w.get("direct_tpidr_callee_overlap") for w in writer_summaries)
    tpidr_called_by_writer = any(t.get("called_by_global_writer") for t in tpidr_summaries)

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw12_writer_lifetime_closure.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW12",
        "policy": "read_only_ida_trace",
        "input_artifact": RW11,
        "global_anchor": {
            "name": global_anchor.get("name"),
            "ea": global_anchor.get("ea"),
            "write_xref_count": len(write_xrefs),
            "writer_function_count": len(writer_func_starts),
            "write_xrefs": write_xrefs,
            "writer_functions": writer_summaries,
        },
        "tpidr_functions": tpidr_summaries,
        "closure_checks": {
            "global_writer_directly_calls_tpidr_heavy_function": bool(writer_reaches_tpidr),
            "tpidr_heavy_function_directly_called_by_global_writer": bool(tpidr_called_by_writer),
            "writer_function_starts": writer_func_starts,
            "tpidr_function_starts": tpidr_starts,
        },
        "summary": {
            "global_writer_function_count": len(writer_func_starts),
            "global_write_xref_count": len(write_xrefs),
            "tpidr_function_count": len(tpidr_starts),
            "writer_reaches_tpidr_directly": bool(writer_reaches_tpidr),
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_writer_lifetime_closure",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW12 identifies the global writer and local lifetime context, but does not yet prove owner/resource identity suitable for S06.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW12 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
