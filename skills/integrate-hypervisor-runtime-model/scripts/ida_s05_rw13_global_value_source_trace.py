"""IDA-side S05-RW13 global value-source and consumer trace.

This read-only IDAPython script consumes S05-RW11/RW12 outputs and asks a
narrow question:

- where does the value written to the dominant global anchor come from?
- how is that global anchor consumed by readers?

It is intentionally evidence-only. It never renames, comments, creates
functions, applies types, or mutates the IDB.
"""

from __future__ import annotations

import json
import os
import re

import ida_bytes
import ida_funcs
import ida_kernwin
import idautils
import idc


ROOT = os.environ.get("BINREV_ROOT", r"F:\AI\codexProject\binRev")
S05 = os.path.join(ROOT, "cases", "xen_arm64-778090a1", "stages", "S05")
RW11 = os.environ.get("BINREV_S05_RW11", os.path.join(S05, "s05-rw11-anchor-xref-trace.json"))
RW12 = os.environ.get("BINREV_S05_RW12", os.path.join(S05, "s05-rw12-writer-lifetime-closure.json"))
OUT = os.environ.get("BINREV_S05_RW13_OUT", os.path.join(S05, "s05-rw13-global-value-source-trace.json"))


def hx(ea):
    return None if ea is None or ea == idc.BADADDR else hex(int(ea))


def parse_hex(s):
    if s is None:
        return None
    try:
        return int(str(s), 16)
    except Exception:
        return None


def dis(ea):
    return idc.generate_disasm_line(ea, 0) or ""


def mnem(ea):
    return (idc.print_insn_mnem(ea) or "").upper()


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


def fixed_window(ea, before=10, after=10):
    if ea is None:
        return []
    start = max(0, ea - before * 4)
    out = []
    for cur in range(start, ea + (after + 1) * 4, 4):
        out.append(
            {
                "ea": hx(cur),
                "mnem": mnem(cur),
                "text": dis(cur),
                "is_focus": cur == ea,
            }
        )
    return out


def code_targets_from_call(ea):
    text = dis(ea).strip().upper()
    if not (text.startswith("BL") or text.startswith("BLR")):
        return []
    out = []
    for to in idautils.CodeRefsFrom(ea, 0):
        out.append({"ea": hx(to), "function": func_at(to), "text": dis(ea)})
    return out


def scan_writer_value_source(write_ea, writer_start):
    """Find the local producer of the value stored into the global anchor."""
    out = {
        "write_ea": hx(write_ea),
        "writer_function": func_at(writer_start),
        "local_window": fixed_window(write_ea, before=12, after=12),
        "last_w0_producer_before_write": None,
        "nearby_calls_before_write": [],
        "store_operand_text": dis(write_ea),
    }
    if write_ea is None:
        return out

    forwarded_ea = None
    for cur in range(write_ea - 4, max(writer_start, write_ea - 80) - 1, -4):
        text = dis(cur)
        upper = text.upper()
        # In the observed branch, MOV W1, W0 forwards the return value into STR W1.
        if re.search(r"\bMOV\s+W1,\s*W0\b", upper):
            forwarded_ea = cur
            out["last_w0_producer_before_write"] = {
                "kind": "return_value_forwarded_by_mov_w1_w0",
                "ea": hx(cur),
                "text": text,
                "producer_call_candidates": [],
            }
            break
        if re.search(r"\b(W1|X1)\b", upper) and upper.startswith(("MOV", "ORR", "ADD", "SUB", "LDR", "ADRP")):
            out["last_w0_producer_before_write"] = {
                "kind": "direct_w1_definition",
                "ea": hx(cur),
                "text": text,
                "producer_call_candidates": list(out["nearby_calls_before_write"]),
            }
            break

    # If W1 is populated from W0, keep scanning backwards from the forwarding
    # instruction to capture the nearest call returning W0. The earlier version
    # stopped at MOV W1,W0 and missed `BL sub_C18A0`, which made the trace
    # under-informative despite correct local forwarding detection.
    if forwarded_ea is not None:
        producer_calls = []
        for cur in range(forwarded_ea - 4, max(writer_start, forwarded_ea - 80) - 1, -4):
            text = dis(cur)
            upper = text.upper().strip()
            if upper.startswith("BL"):
                producer_calls.append({"ea": hx(cur), "text": text, "targets": code_targets_from_call(cur)})
                if len(producer_calls) >= 8:
                    break
        out["nearby_calls_before_write"] = producer_calls
        out["last_w0_producer_before_write"]["producer_call_candidates"] = producer_calls
    return out


def scan_return_value_defs(f, limit=80):
    """Collect return sites and the closest W0/X0 definition before RET."""
    out = []
    if not f:
        return out
    for ea in idautils.FuncItems(f.start_ea):
        if mnem(ea) != "RET":
            continue
        item = {
            "ret_ea": hx(ea),
            "ret_text": dis(ea),
            "window": fixed_window(ea, before=10, after=2),
            "nearest_x0_w0_defs": [],
        }
        for cur in range(ea - 4, max(f.start_ea, ea - 80) - 1, -4):
            text = dis(cur)
            upper = text.upper()
            if re.search(r"\b(W0|X0)\b", upper) and upper.startswith(
                ("MOV", "MOVZ", "MOVK", "LDR", "ADRP", "ADD", "SUB", "AND", "ORR", "EOR", "CSEL", "CSINC", "UBFX", "SBFM")
            ):
                item["nearest_x0_w0_defs"].append({"ea": hx(cur), "mnem": mnem(cur), "text": text})
                if len(item["nearest_x0_w0_defs"]) >= 4:
                    break
        out.append(item)
        if len(out) >= limit:
            break
    return out


def summarize_function(start_s, return_value=False):
    f = func_by_start(start_s)
    summary = {"function": func_at(parse_hex(start_s)), "exists": bool(f)}
    if not f:
        return summary

    calls = []
    for ea in idautils.FuncItems(f.start_ea):
        if mnem(ea).startswith("BL"):
            calls.append({"ea": hx(ea), "text": dis(ea), "targets": code_targets_from_call(ea)})
            if len(calls) >= 80:
                break

    strings = []
    string_map = {}
    try:
        string_map = {int(s.ea): str(s) for s in idautils.Strings()}
    except Exception:
        string_map = {}
    for ea in idautils.FuncItems(f.start_ea):
        for dr in idautils.DataRefsFrom(ea):
            if dr in string_map:
                strings.append({"from": hx(ea), "string_ea": hx(dr), "text": string_map[dr]})
                if len(strings) >= 40:
                    break
        if len(strings) >= 40:
            break

    summary.update(
        {
            "call_count_sampled": len(calls),
            "calls": calls,
            "strings": strings,
            "return_value_defs": scan_return_value_defs(f) if return_value else [],
        }
    )
    return summary


def classify_consumer_window(window):
    text = "\n".join(w.get("text", "").upper() for w in window)
    tags = []
    if re.search(r"\b(CMP|TST|CBZ|CBNZ|TBZ|TBNZ)\b", text):
        tags.append("condition_or_limit_check")
    if re.search(r"\b(LSL|UXTW|SXTW)\b", text):
        tags.append("index_or_scaled_access")
    if re.search(r"\b(LDR|STR)\b", text):
        tags.append("memory_access_near_anchor")
    if re.search(r"\b(B\.|B\s|BL\s)", text):
        tags.append("control_flow_near_anchor")
    if not tags:
        tags.append("unclassified_local_use")
    return tags


def summarize_global_consumers(global_anchor, max_functions=40):
    grouped = {}
    for xr in global_anchor.get("xrefs", []):
        fn = xr.get("function") or {}
        start = fn.get("start")
        if not start:
            continue
        bucket = grouped.setdefault(
            start,
            {
                "function": fn,
                "kind_counts": {},
                "samples": [],
            },
        )
        kind = xr.get("kind") or "unknown"
        bucket["kind_counts"][kind] = bucket["kind_counts"].get(kind, 0) + 1
        if len(bucket["samples"]) < 5:
            ea = parse_hex(xr.get("from"))
            win = fixed_window(ea, before=2, after=8)
            bucket["samples"].append(
                {
                    "xref_from": xr.get("from"),
                    "xref_kind": kind,
                    "xref_text": xr.get("text"),
                    "window": win,
                    "consumer_tags": classify_consumer_window(win),
                }
            )

    def score(item):
        counts = item[1]["kind_counts"]
        return (counts.get("read", 0) * 3 + counts.get("write", 0) * 5 + counts.get("address_calc", 0), sum(counts.values()))

    consumers = [v for _, v in sorted(grouped.items(), key=score, reverse=True)[:max_functions]]
    tag_counts = {}
    for c in consumers:
        local = set()
        for s in c.get("samples", []):
            for t in s.get("consumer_tags", []):
                local.add(t)
        c["consumer_tags_union"] = sorted(local)
        for t in local:
            tag_counts[t] = tag_counts.get(t, 0) + 1
    return {"function_count": len(grouped), "top_consumers": consumers, "tag_counts_in_top_consumers": tag_counts}


def main():
    with open(RW11, "r", encoding="utf-8") as fp:
        rw11 = json.load(fp)
    with open(RW12, "r", encoding="utf-8") as fp:
        rw12 = json.load(fp)

    global_anchor = rw11.get("global_anchors", [{}])[0]
    write_xrefs = [x for x in global_anchor.get("xrefs", []) if x.get("kind") == "write"]

    writer_value_sources = []
    return_source_functions = {}
    for xr in write_xrefs:
        write_ea = parse_hex(xr.get("from"))
        writer_start = parse_hex((xr.get("function") or {}).get("start"))
        source = scan_writer_value_source(write_ea, writer_start or 0)
        writer_value_sources.append(source)
        producer = source.get("last_w0_producer_before_write") or {}
        calls = producer.get("producer_call_candidates") or []
        if calls:
            # Calls are collected nearest-first because the scan walks backwards.
            nearest = calls[0]
            targets = nearest.get("targets") or []
            for target in targets:
                tf = target.get("function") or func_at(parse_hex(target.get("ea")))
                if tf and tf.get("start"):
                    return_source_functions[tf["start"]] = summarize_function(tf["start"], return_value=True)

    consumers = summarize_global_consumers(global_anchor)

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw13_global_value_source_trace.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW13",
        "policy": "read_only_ida_trace",
        "input_artifacts": [RW11, RW12],
        "global_anchor": {
            "name": global_anchor.get("name"),
            "ea": global_anchor.get("ea"),
            "writer_value_sources": writer_value_sources,
            "return_source_functions": list(return_source_functions.values()),
            "consumer_summary": consumers,
        },
        "rw12_closure_summary": rw12.get("summary", {}),
        "summary": {
            "global_anchor": global_anchor.get("name"),
            "write_xref_count": len(write_xrefs),
            "return_source_function_count": len(return_source_functions),
            "consumer_function_count": consumers.get("function_count"),
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_global_value_source_trace",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW13 traces global value source and consumers, but does not promote a global scalar/config/count into an object owner without resource identity closure.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW13 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
