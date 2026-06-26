"""IDA-side S05-RW15 TPIDR offset writer/lifecycle trace.

This read-only IDAPython script consumes RW14 TPIDR offset families and scans
the full IDB for writes/clears/atomic uses of those offsets. It also performs a
simple function-local TPIDR-derived pointer propagation to separate:

- confirmed local TPIDR-derived field writes/clears
- generic same-offset writes that may be initializers/teardown candidates
- read-only TPIDR field families that still block S06 ownership promotion

It never mutates IDA.
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
RW14 = os.environ.get("BINREV_S05_RW14", os.path.join(S05, "s05-rw14-tpidr-offset-family-trace.json"))
OUT = os.environ.get("BINREV_S05_RW15_OUT", os.path.join(S05, "s05-rw15-tpidr-writer-lifecycle-trace.json"))


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


def regs_in_text(text):
    return {norm_reg(x) for x in REG_TOKEN_RE.findall(text.upper()) if norm_reg(x)}


def first_dest_reg(text):
    m = re.match(r"\s*[A-Z0-9.]+\s+(" + REG_RE + r")\s*,", text, re.I)
    return norm_reg(m.group(1)) if m else None


def first_src_reg(text):
    m = re.match(r"\s*[A-Z0-9.]+\s+" + REG_RE + r"\s*,\s*(" + REG_RE + r")\b", text, re.I)
    return norm_reg(m.group(1)) if m else None


def store_value_reg(text):
    mn = (text or "").strip().split(None, 1)[0].upper() if text and text.strip() else ""
    if not (mn.startswith("ST") or mn in {"STR", "STP"}):
        return None
    m = re.match(r"\s*[A-Z0-9.]+\s+(" + REG_RE + r")\s*,", text, re.I)
    return norm_reg(m.group(1)) if m else None


def parse_mem(text):
    out = []
    for m in MEM_RE.finditer(text):
        base = norm_reg(m.group(1))
        rest = (m.group(2) or "").upper()
        regs = {norm_reg(x) for x in REG_TOKEN_RE.findall(rest) if norm_reg(x)}
        imm = None
        rest_stripped = rest.strip()
        if rest_stripped.startswith("#"):
            mi = re.match(r"#(-?0X[0-9A-F]+|-?\d+)", rest_stripped, re.I)
            if mi:
                try:
                    imm = int(mi.group(1), 0)
                except Exception:
                    imm = None
        out.append({"base": base, "index_regs": sorted(regs), "imm": imm, "raw": m.group(0)})
    return out


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


def code_call_targets(ea):
    text = dis(ea).strip().upper()
    if not text.startswith("BL"):
        return []
    out = []
    for to in idautils.CodeRefsFrom(ea, 0):
        out.append({"ea": hx(to), "function": func_at(to), "text": dis(ea)})
    return out


def nearby_window(ea, before=6, after=8):
    start = max(0, ea - before * 4)
    return [
        {"ea": hx(cur), "mnem": mnem(cur), "text": dis(cur), "is_focus": cur == ea}
        for cur in range(start, ea + (after + 1) * 4, 4)
    ]


def classify_store_value(f, ea, value_reg):
    if not value_reg:
        return {"kind": "unknown_value"}
    if value_reg in {"XZR", "WZR"}:
        return {"kind": "zero_register_clear"}

    # Walk back a few instructions for a direct zero/immediate assignment.
    for cur in range(ea - 4, max(f.start_ea, ea - 32) - 1, -4):
        text = dis(cur).upper()
        dest = first_dest_reg(text)
        if dest != value_reg:
            continue
        if re.search(r"\bMOV\s+" + re.escape(value_reg.replace("X", "[XW]", 1)) + r"\s*,\s*#0\b", text):
            return {"kind": "recent_zero_mov", "source_ea": hx(cur), "source_text": dis(cur)}
        if "#0" in text and mnem(cur) in {"MOV", "MOVZ"}:
            return {"kind": "recent_zero_like", "source_ea": hx(cur), "source_text": dis(cur)}
        return {"kind": "recent_nonzero_definition", "source_ea": hx(cur), "source_text": dis(cur)}
    return {"kind": "untraced_value_reg", "value_reg": value_reg}


def event_kind(ea):
    mn = mnem(ea)
    if mn.startswith("LDXR") or mn.startswith("STXR") or mn.startswith("STLXR") or mn.startswith("CAS"):
        return "atomic"
    if mn.startswith("ST"):
        return "write"
    if mn.startswith("LD"):
        return "read"
    return "other"


def load_target_offsets(rw14):
    offsets = []
    for item in rw14.get("global_offset_families", []):
        off = parse_hex(item.get("offset"))
        if off is not None:
            offsets.append(off)
    return sorted(set(offsets))


def scan_same_offset_all_functions(target_offsets):
    """Find all same-offset memory operations, independent of TPIDR proof."""
    by_offset = {off: {"offset": hex(off), "read": 0, "write": 0, "atomic": 0, "other": 0, "functions": {}, "samples": []} for off in target_offsets}
    target_set = set(target_offsets)
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        fn = func_at(f.start_ea)
        function_has_tpidr = False
        function_events = []
        for ea in idautils.FuncItems(f.start_ea):
            text = dis(ea)
            if "TPIDR_EL2" in text.upper():
                function_has_tpidr = True
            for mem in parse_mem(text):
                imm = mem.get("imm")
                if imm not in target_set:
                    continue
                kind = event_kind(ea)
                bucket = by_offset[imm]
                bucket[kind] = bucket.get(kind, 0) + 1
                function_events.append({"ea": hx(ea), "kind": kind, "text": text, "mem": mem})
                if len(bucket["samples"]) < 80:
                    bucket["samples"].append({"ea": hx(ea), "kind": kind, "text": text, "function": fn, "mem": mem})
        for ev in function_events:
            off = ev["mem"]["imm"]
            rec = by_offset[off]["functions"].setdefault(fn["start"], {"function": fn, "read": 0, "write": 0, "atomic": 0, "other": 0, "has_tpidr": function_has_tpidr, "samples": []})
            rec[ev["kind"]] = rec.get(ev["kind"], 0) + 1
            if len(rec["samples"]) < 12:
                rec["samples"].append(ev)

    out = []
    for off, bucket in by_offset.items():
        funcs = list(bucket.pop("functions").values())
        funcs.sort(key=lambda x: (-(x.get("write", 0) + x.get("atomic", 0)), -x.get("read", 0), x["function"]["start"]))
        bucket["function_count"] = len(funcs)
        bucket["writer_function_count"] = sum(1 for x in funcs if x.get("write", 0) or x.get("atomic", 0))
        bucket["tpidr_function_count"] = sum(1 for x in funcs if x.get("has_tpidr"))
        bucket["top_functions"] = funcs[:30]
        out.append(bucket)
    out.sort(key=lambda x: (-(x.get("write", 0) + x.get("atomic", 0)), -x.get("read", 0), x["offset"]))
    return out


def propagate_tpidr_in_function(f, target_offsets):
    regs = {}
    target_set = set(target_offsets)
    derived_events = []
    calls_near_events = []
    has_tpidr = False

    for ea in idautils.FuncItems(f.start_ea):
        text = dis(ea)
        upper = text.upper()
        mn = mnem(ea)
        dest = first_dest_reg(text)

        if "TPIDR_EL2" in upper and "MRS" in upper and dest:
            regs[dest] = {"class": "tpidr_value", "origin": hx(ea)}
            has_tpidr = True
            continue

        mems = parse_mem(text)
        touched = False
        for mem in mems:
            base_cls = regs.get(mem["base"], {}).get("class")
            index_classes = [regs.get(r, {}).get("class") for r in mem["index_regs"] if r in regs]
            interesting = base_cls or any(index_classes)

            if dest and mn.startswith("LD"):
                if "tpidr_value" in index_classes:
                    regs[dest] = {"class": "percpu_slot_ptr", "origin": hx(ea)}
                elif base_cls in {"percpu_slot_ptr", "tpidr_loaded_ptr", "tpidr_field_ptr"}:
                    regs[dest] = {"class": "tpidr_loaded_ptr", "origin": hx(ea)}
                elif base_cls == "tpidr_value":
                    regs[dest] = {"class": "tpidr_field_ptr", "origin": hx(ea)}

            if not interesting:
                continue
            touched = True
            imm = mem.get("imm")
            kind = event_kind(ea)
            if imm in target_set:
                value_reg = store_value_reg(text)
                event = {
                    "ea": hx(ea),
                    "kind": kind,
                    "text": text,
                    "mem": mem,
                    "base_class": base_cls,
                    "index_classes": [x for x in index_classes if x],
                    "value_reg": value_reg,
                    "value_classification": classify_store_value(f, ea, value_reg) if kind in {"write", "atomic"} else None,
                    "window": nearby_window(ea),
                }
                derived_events.append(event)

        if mn.startswith("BL"):
            targets = code_call_targets(ea)
            arg_classes = {r: regs[r] for r in ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"] if r in regs}
            if arg_classes:
                calls_near_events.append({"ea": hx(ea), "text": text, "targets": targets, "arg_classes": arg_classes})

        if not touched and dest:
            src_regs = regs_in_text(upper)
            src_classes = [regs.get(r, {}).get("class") for r in src_regs if r != dest and r in regs]
            if src_classes and mn in {"MOV", "ADD", "SUB", "AND", "ORR", "EOR", "LSL", "LSR", "SXTW", "UXTW"}:
                regs[dest] = {"class": src_classes[0], "origin": hx(ea), "via": text}
            elif dest in regs and mn not in {"CMP", "TST", "CBZ", "CBNZ"}:
                regs.pop(dest, None)

    return {"has_tpidr": has_tpidr, "derived_events": derived_events, "calls_with_tpidr_args": calls_near_events}


def scan_tpidr_confirmed_functions(target_offsets):
    out = []
    for f_ea in idautils.Functions():
        f = ida_funcs.get_func(f_ea)
        if not f:
            continue
        scan = propagate_tpidr_in_function(f, target_offsets)
        if not scan["has_tpidr"] and not scan["derived_events"] and not scan["calls_with_tpidr_args"]:
            continue
        if not scan["derived_events"] and not scan["calls_with_tpidr_args"]:
            continue
        derived = scan["derived_events"]
        out.append(
            {
                "function": func_at(f.start_ea),
                "derived_event_count": len(derived),
                "derived_write_count": sum(1 for x in derived if x["kind"] in {"write", "atomic"}),
                "derived_read_count": sum(1 for x in derived if x["kind"] == "read"),
                "calls_with_tpidr_arg_count": len(scan["calls_with_tpidr_args"]),
                "derived_events": derived[:80],
                "calls_with_tpidr_args": scan["calls_with_tpidr_args"][:80],
            }
        )
    out.sort(key=lambda x: (-x["derived_write_count"], -x["calls_with_tpidr_arg_count"], -x["derived_read_count"], x["function"]["start"]))
    return out


def summarize_lifecycle_candidates(same_offset, confirmed):
    candidates = []
    for off in same_offset:
        offset = off["offset"]
        writer_funcs = [f for f in off.get("top_functions", []) if f.get("write") or f.get("atomic")]
        clearish = []
        for f in writer_funcs[:20]:
            for sample in f.get("samples", []):
                text = sample.get("text", "").upper()
                if "XZR" in text or "WZR" in text or "#0" in text:
                    clearish.append({"offset": offset, "function": f.get("function"), "sample": sample})
                    break
        candidates.append(
            {
                "offset": offset,
                "same_offset_writer_function_count": off.get("writer_function_count", 0),
                "same_offset_tpidr_function_count": off.get("tpidr_function_count", 0),
                "clearish_writer_count": len(clearish),
                "top_clearish_writers": clearish[:10],
                "decision": "review_required_same_offset_lifecycle_candidates" if writer_funcs else "read_only_no_writer_seen",
            }
        )

    confirmed_writer_offsets = {}
    for fn in confirmed:
        for ev in fn.get("derived_events", []):
            if ev.get("kind") in {"write", "atomic"}:
                off = ev.get("mem", {}).get("imm")
                if off is not None:
                    confirmed_writer_offsets.setdefault(hex(off), []).append({"function": fn["function"], "event": ev})

    return {
        "same_offset_lifecycle_candidates": candidates,
        "confirmed_tpidr_writer_offsets": [
            {"offset": k, "writer_count": len(v), "writers": v[:20]}
            for k, v in sorted(confirmed_writer_offsets.items(), key=lambda kv: (-len(kv[1]), kv[0]))
        ],
    }


def main():
    with open(RW14, "r", encoding="utf-8") as fp:
        rw14 = json.load(fp)

    offsets = load_target_offsets(rw14)
    same_offset = scan_same_offset_all_functions(offsets)
    confirmed = scan_tpidr_confirmed_functions(offsets)
    lifecycle = summarize_lifecycle_candidates(same_offset, confirmed)

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw15_tpidr_writer_lifecycle_trace.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW15",
        "policy": "read_only_ida_trace",
        "input_artifact": RW14,
        "target_offsets": [hex(x) for x in offsets],
        "same_offset_all_functions": same_offset,
        "tpidr_confirmed_functions": confirmed[:80],
        "lifecycle_candidate_summary": lifecycle,
        "summary": {
            "target_offset_count": len(offsets),
            "same_offset_writer_offsets": sum(1 for x in same_offset if x.get("writer_function_count", 0) > 0),
            "same_offset_writer_function_total": sum(x.get("writer_function_count", 0) for x in same_offset),
            "tpidr_confirmed_function_count": len(confirmed),
            "tpidr_confirmed_writer_function_count": sum(1 for x in confirmed if x.get("derived_write_count", 0) > 0),
            "confirmed_tpidr_writer_offset_count": len(lifecycle["confirmed_tpidr_writer_offsets"]),
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_tpidr_writer_lifecycle_trace",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW15 finds writer/clearer candidates for TPIDR offset families but keeps them review-only until init/start/stop/destroy resource identity closure is proven.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW15 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
