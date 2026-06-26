"""IDA-side S05-RW14 TPIDR offset-family trace.

This read-only IDAPython script follows short local dataflow windows after
`MRS <reg>, TPIDR_EL2` to identify TPIDR-indexed slots and field-offset
families. It is deliberately conservative: it emits review evidence only and
does not mutate IDA.
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
OUT = os.environ.get("BINREV_S05_RW14_OUT", os.path.join(S05, "s05-rw14-tpidr-offset-family-trace.json"))


REG_RE = r"(?:X|W)(?:[0-9]|[12][0-9]|3[01])|SP|XZR|WZR"
REG_TOKEN_RE = re.compile(r"(?<![A-Z0-9_])(" + REG_RE + r")(?![A-Z0-9_])", re.I)
MEM_RE = re.compile(r"\[([XW](?:[0-9]|[12][0-9]|3[01])|SP)(?:,([^\]]+))?\]", re.I)


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


def norm_reg(reg):
    if not reg:
        return None
    reg = reg.upper().strip()
    if reg.startswith("W") and reg[1:].isdigit():
        return "X" + reg[1:]
    return reg


def first_dest_reg(text):
    m = re.match(r"\s*[A-Z0-9.]+\s+(" + REG_RE + r")\s*,", text, re.I)
    return norm_reg(m.group(1)) if m else None


def regs_in_text(text):
    return {norm_reg(x) for x in REG_TOKEN_RE.findall(text.upper()) if norm_reg(x)}


def parse_mem(text):
    out = []
    for m in MEM_RE.finditer(text):
        base = norm_reg(m.group(1))
        rest = (m.group(2) or "").upper()
        regs = {norm_reg(x) for x in REG_TOKEN_RE.findall(rest) if norm_reg(x)}
        imm = None
        # Treat only base+immediate forms like [X0,#0x18] as field offsets.
        # Do not treat shift scales in [X0,X1,LSL#3] as offsets.
        rest_stripped = rest.strip()
        if rest_stripped.startswith("#"):
            mi = re.match(r"#(-?0X[0-9A-F]+|-?\d+)", rest_stripped, re.I)
            if mi:
                raw = mi.group(1).replace("#", "")
                try:
                    imm = int(raw, 0)
                except Exception:
                    imm = None
        out.append({"base": base, "index_regs": sorted(regs), "imm": imm, "raw": m.group(0)})
    return out


def func_at(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return None
    return {"start": hx(f.start_ea), "end": hx(f.end_ea), "name": ida_funcs.get_func_name(f.start_ea)}


def is_call_or_barrier(ea):
    mn = mnem(ea)
    return mn in {"BL", "BLR", "RET", "ERET"} or mn.startswith("B.")


def trace_from_mrs(mrs_ea, dest_reg, max_insns=28):
    regs = {norm_reg(dest_reg): {"class": "tpidr_value", "origin": hx(mrs_ea)}}
    events = []
    field_offsets = {}
    slot_loads = []

    f = ida_funcs.get_func(mrs_ea)
    end_ea = f.end_ea if f else mrs_ea + max_insns * 4
    cur = mrs_ea + 4
    steps = 0
    while cur < end_ea and steps < max_insns:
        text = dis(cur)
        mn = mnem(cur)
        mems = parse_mem(text)
        dest = first_dest_reg(text)
        touched = False

        for mem in mems:
            base_cls = regs.get(mem["base"], {}).get("class")
            index_classes = [regs.get(r, {}).get("class") for r in mem["index_regs"] if r in regs]
            interesting = base_cls or any(index_classes)
            if not interesting:
                continue

            touched = True
            kind = "read"
            if mn.startswith("ST"):
                kind = "write"
            elif mn.startswith("LDXR") or mn.startswith("STXR") or mn.startswith("STLXR"):
                kind = "atomic"

            event = {
                "ea": hx(cur),
                "mnem": mn,
                "kind": kind,
                "text": text,
                "mem": mem,
                "base_class": base_cls,
                "index_classes": [x for x in index_classes if x],
            }
            events.append(event)

            if base_cls in {"percpu_slot_ptr", "tpidr_field_ptr", "tpidr_loaded_ptr"} and mem.get("imm") is not None:
                key = hex(mem["imm"])
                bucket = field_offsets.setdefault(key, {"offset": key, "read": 0, "write": 0, "atomic": 0, "samples": []})
                bucket[kind] = bucket.get(kind, 0) + 1
                if len(bucket["samples"]) < 8:
                    bucket["samples"].append(event)

            if dest and mn.startswith("LD"):
                if "tpidr_value" in index_classes:
                    regs[dest] = {"class": "percpu_slot_ptr", "origin": hx(cur)}
                    slot_loads.append(event)
                elif base_cls in {"percpu_slot_ptr", "tpidr_field_ptr", "tpidr_loaded_ptr"}:
                    regs[dest] = {"class": "tpidr_loaded_ptr", "origin": hx(cur)}
                elif base_cls == "tpidr_value":
                    regs[dest] = {"class": "tpidr_field_ptr", "origin": hx(cur)}

        # Simple register copy/arith propagation.
        if not touched and dest:
            text_upper = text.upper()
            src_regs = regs_in_text(text_upper)
            src_classes = [regs.get(r, {}).get("class") for r in src_regs if r != dest and r in regs]
            if src_classes and mn in {"MOV", "ADD", "SUB", "AND", "ORR", "EOR", "LSL", "LSR", "SXTW", "UXTW"}:
                regs[dest] = {"class": src_classes[0], "origin": hx(cur), "via": text}
            elif dest in regs and mn not in {"CMP", "TST", "CBZ", "CBNZ"}:
                # Conservative clobber when the destination is overwritten by
                # something unrelated.
                regs.pop(dest, None)

        if is_call_or_barrier(cur):
            break
        cur += 4
        steps += 1

    return {
        "mrs_ea": hx(mrs_ea),
        "dest_reg": norm_reg(dest_reg),
        "events": events,
        "slot_loads": slot_loads,
        "field_offsets": sorted(field_offsets.values(), key=lambda x: (-(x.get("write", 0) + x.get("atomic", 0)), x["offset"])),
        "event_count": len(events),
        "slot_load_count": len(slot_loads),
    }


def summarize_function(tpidr_item):
    fn = tpidr_item.get("function") or {}
    start = parse_hex(fn.get("start") or tpidr_item.get("requested_start"))
    traces = []
    for read in tpidr_item.get("tpidr_reads", []):
        ea = parse_hex(read.get("ea"))
        if ea is None:
            continue
        traces.append(trace_from_mrs(ea, read.get("dest_reg")))

    offset_summary = {}
    slot_trace_count = 0
    event_count = 0
    for tr in traces:
        slot_trace_count += 1 if tr.get("slot_load_count") else 0
        event_count += tr.get("event_count", 0)
        for off in tr.get("field_offsets", []):
            bucket = offset_summary.setdefault(off["offset"], {"offset": off["offset"], "read": 0, "write": 0, "atomic": 0, "samples": []})
            for k in ("read", "write", "atomic"):
                bucket[k] += off.get(k, 0)
            for sample in off.get("samples", []):
                if len(bucket["samples"]) < 8:
                    bucket["samples"].append(sample)

    offsets = sorted(offset_summary.values(), key=lambda x: (-(x["write"] + x["atomic"]), -x["read"], x["offset"]))
    return {
        "function": func_at(start) if start is not None else fn,
        "tpidr_read_count": len(tpidr_item.get("tpidr_reads", [])),
        "trace_count": len(traces),
        "trace_with_slot_load_count": slot_trace_count,
        "interesting_event_count": event_count,
        "top_field_offsets": offsets[:40],
        "trace_samples": traces[:20],
        "decision": "review_required_tpidr_offset_family_trace",
    }


def main():
    with open(RW11, "r", encoding="utf-8") as fp:
        rw11 = json.load(fp)

    functions = [summarize_function(x) for x in rw11.get("tpidr_functions", [])]
    functions.sort(key=lambda x: (x.get("trace_with_slot_load_count", 0), x.get("interesting_event_count", 0)), reverse=True)

    offset_global = {}
    for fn in functions:
        for off in fn.get("top_field_offsets", []):
            bucket = offset_global.setdefault(off["offset"], {"offset": off["offset"], "read": 0, "write": 0, "atomic": 0, "function_count": 0, "functions": []})
            bucket["function_count"] += 1
            for k in ("read", "write", "atomic"):
                bucket[k] += off.get(k, 0)
            if len(bucket["functions"]) < 12:
                bucket["functions"].append(fn.get("function"))
    global_offsets = sorted(offset_global.values(), key=lambda x: (-(x["write"] + x["atomic"]), -x["read"], x["offset"]))

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw14_tpidr_offset_family_trace.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW14",
        "policy": "read_only_ida_trace",
        "input_artifact": RW11,
        "functions": functions,
        "global_offset_families": global_offsets[:80],
        "summary": {
            "tpidr_function_count": len(functions),
            "functions_with_slot_loads": sum(1 for f in functions if f.get("trace_with_slot_load_count")),
            "interesting_event_count": sum(f.get("interesting_event_count", 0) for f in functions),
            "global_offset_family_count": len(global_offsets),
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_tpidr_offset_family_trace",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW14 identifies TPIDR-indexed slot/field families but still requires lifecycle/resource identity before ownership promotion.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW14 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
