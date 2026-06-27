"""Export all IDA functions and ARM64 architecture events for workflow v2.

Run inside IDA via MCP run_script. The script writes corpus-wide S03/S04/S07
artifacts and does not mutate the IDB.
"""

import json
from pathlib import Path

import ida_auto
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_lines
import ida_segment
import ida_xref
import idautils
import idc


ROOT = Path(r"F:\AI\codexProject\binRev")
CASE_ID = "round2-xen_arm64-778090a1"
CASE = ROOT / "cases" / CASE_ID
S03 = CASE / "stages" / "S03"
S04 = CASE / "stages" / "S04"
S07 = CASE / "stages" / "S07"

SYSREG_TOKENS = [
    "HCR_EL2",
    "SCTLR_EL2",
    "TCR_EL2",
    "TTBR0_EL2",
    "TTBR1_EL2",
    "VTCR_EL2",
    "VTTBR_EL2",
    "VBAR_EL2",
    "ESR_EL2",
    "FAR_EL2",
    "HPFAR_EL2",
    "TPIDR_EL2",
    "CNTHCTL_EL2",
    "CNTVOFF_EL2",
    "CNTP_CTL_EL0",
    "CNTHP_CTL_EL2",
    "MPIDR_EL1",
    "CurrentEL",
]

ARCH_TOKENS = [
    "TLBI",
    "DSB",
    "DMB",
    "ISB",
    "WFE",
    "WFI",
    "ERET",
    "SMC",
    "HVC",
    "MSR",
    "MRS",
    "IC ",
    "DC ",
]


def hx(ea):
    if ea is None or ea == idc.BADADDR:
        return None
    return "0x%x" % int(ea)


def clean(s):
    return ida_lines.tag_remove(str(s or ""))


def disasm_line(ea):
    return clean(idc.generate_disasm_line(ea, 0))


def iter_functions():
    for ea in idautils.Functions():
        f = ida_funcs.get_func(ea)
        if f:
            yield f


def chunks(f):
    return [{"start": hx(a), "end": hx(b)} for a, b in idautils.Chunks(f.start_ea)]


def decompile_lines(f):
    try:
        cfunc = ida_hexrays.decompile(f.start_ea)
        if not cfunc:
            return {"ok": False, "error": "decompile returned None", "lines": []}
        return {"ok": True, "error": None, "lines": [clean(x.line) for x in cfunc.get_pseudocode()]}
    except Exception as e:
        return {"ok": False, "error": repr(e), "lines": []}


def function_items(f, limit=20000):
    rows = []
    count = 0
    for ea in idautils.FuncItems(f.start_ea):
        if count >= limit:
            rows.append({"ea": hx(ea), "text": "<truncated>"})
            break
        rows.append({"ea": hx(ea), "text": disasm_line(ea)})
        count += 1
    return rows


def cref_targets(ea):
    rows = []
    xr = ida_xref.get_first_cref_from(ea)
    while xr != idc.BADADDR:
        tf = ida_funcs.get_func(xr)
        rows.append({"from": hx(ea), "to": hx(xr), "target_function": hx(tf.start_ea) if tf else None})
        xr = ida_xref.get_next_cref_from(ea, xr)
    return rows


def cref_sources(ea):
    rows = []
    xr = ida_xref.get_first_cref_to(ea)
    while xr != idc.BADADDR:
        sf = ida_funcs.get_func(xr)
        rows.append({"from": hx(xr), "source_function": hx(sf.start_ea) if sf else None, "line": disasm_line(xr)})
        xr = ida_xref.get_next_cref_to(ea, xr)
    return rows


def classify_arch_event(text):
    hits = []
    for token in SYSREG_TOKENS:
        if token in text:
            hits.append({"kind": "sysreg", "token": token})
    for token in ARCH_TOKENS:
        if token in text:
            hits.append({"kind": "instruction", "token": token.strip()})
    if "GIC" in text or "ICC_" in text or "ICH_" in text:
        hits.append({"kind": "interrupt", "token": "GIC/ICC/ICH"})
    if "SMMU" in text:
        hits.append({"kind": "smmu", "token": "SMMU"})
    return hits


def executable_segments():
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        name = ida_segment.get_segm_name(seg) or ""
        if name == ".text" or (seg.perm & ida_segment.SEGPERM_EXEC):
            yield seg


def scan_unowned_code_ranges():
    ranges = []
    for seg in executable_segments():
        cur = seg.start_ea
        open_start = None
        last = None
        while cur < seg.end_ea:
            flags = ida_bytes.get_full_flags(cur)
            in_func = ida_funcs.get_func(cur) is not None
            is_code = ida_bytes.is_code(flags)
            if is_code and not in_func:
                if open_start is None:
                    open_start = cur
                last = cur + ida_bytes.get_item_size(cur)
            else:
                if open_start is not None:
                    ranges.append({"start": hx(open_start), "end": hx(last), "classification": "unowned_code"})
                    open_start = None
                    last = None
            nxt = ida_bytes.get_item_end(cur)
            if nxt == idc.BADADDR or nxt <= cur:
                cur += 4
            else:
                cur = nxt
        if open_start is not None:
            ranges.append({"start": hx(open_start), "end": hx(last), "classification": "unowned_code"})
    return ranges


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def main():
    ida_auto.auto_wait()
    funcs = list(iter_functions())
    func_starts = {f.start_ea for f in funcs}
    function_rows = []
    decompile_rows = []
    arch_events = []
    call_edges = []
    boundary_issues = []

    for index, f in enumerate(funcs):
        name = clean(idc.get_func_name(f.start_ea))
        item_rows = function_items(f)
        callees = set()
        callers = set()
        for item in item_rows:
            ea = int(item["ea"], 16)
            for edge in cref_targets(ea):
                call_edges.append(edge)
                if edge["target_function"]:
                    callees.add(edge["target_function"])
            text = item.get("text") or ""
            for hit in classify_arch_event(text):
                arch_events.append(
                    {
                        "function": hx(f.start_ea),
                        "ea": item["ea"],
                        "line": text,
                        "kind": hit["kind"],
                        "token": hit["token"],
                    }
                )
        for xr in cref_sources(f.start_ea):
            if xr["source_function"]:
                callers.add(xr["source_function"])
        chunk_rows = chunks(f)
        if len(chunk_rows) > 1:
            boundary_issues.append(
                {
                    "function": hx(f.start_ea),
                    "name": name,
                    "kind": "multi_chunk_function",
                    "boundary_status": "candidate_tail_chunk_or_shared_suffix",
                    "chunks": chunk_rows,
                }
            )
        dec = decompile_lines(f)
        boundary_status = "exact_function"
        function_rows.append(
            {
                "index": index,
                "address": hx(f.start_ea),
                "end": hx(f.end_ea),
                "size": f.end_ea - f.start_ea,
                "ida_name": name,
                "boundary_status": boundary_status,
                "chunks": chunk_rows,
                "callers": sorted(callers),
                "callees": sorted(callees),
                "decompile": "available" if dec["ok"] else "missing",
                "decompile_error": dec["error"],
            }
        )
        decompile_rows.append(
            {
                "address": hx(f.start_ea),
                "end": hx(f.end_ea),
                "ida_name": name,
                "size": f.end_ea - f.start_ea,
                "boundary_status": boundary_status,
                "pseudocode": dec,
                "disasm": item_rows,
            }
        )

    sysreg_index = {}
    mmio_index = {}
    exception_events = []
    for ev in arch_events:
        if ev["kind"] == "sysreg":
            sysreg_index.setdefault(ev["token"], []).append(ev)
        if ev["kind"] in {"interrupt", "smmu"}:
            mmio_index.setdefault(ev["token"], []).append(ev)
        if ev["token"] in {"ERET", "HVC", "SMC"} or ev["kind"] == "interrupt":
            exception_events.append(ev)

    unowned = scan_unowned_code_ranges()
    write_jsonl(S03 / "functions.jsonl", function_rows)
    write_json(S03 / "call-graph.json", {"stage_id": "S03", "function_count": len(function_rows), "edges": call_edges})
    write_jsonl(S03 / "function-boundary-issues.jsonl", boundary_issues)
    write_jsonl(S03 / "unowned-code-ranges.jsonl", unowned)
    write_jsonl(S04 / "architecture-events.jsonl", arch_events)
    write_json(S04 / "sysreg-access-index.json", {"stage_id": "S04", "sysregs": sysreg_index})
    write_json(S04 / "mmio-access-index.json", {"stage_id": "S04", "mmio": mmio_index})
    write_json(S04 / "exception-vector-index.json", {"stage_id": "S04", "events": exception_events})
    write_json(
        S07 / "decompile-export-full.json",
        {
            "case_id": CASE_ID,
            "role": "target_production",
            "function_count": len(function_rows),
            "decompiled_count": sum(1 for r in decompile_rows if r["pseudocode"]["ok"]),
            "functions": decompile_rows,
        },
    )
    print(
        json.dumps(
            {
                "case": CASE_ID,
                "functions": len(function_rows),
                "decompiled": sum(1 for r in decompile_rows if r["pseudocode"]["ok"]),
                "arch_events": len(arch_events),
                "boundary_issues": len(boundary_issues),
                "unowned_ranges": len(unowned),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
