"""IDA-side S05-RW17 cross-function argument bridge trace.

Consumes RW16 shared caller/callee bridge pairs and compares argument roots:

- shared caller mode: a caller invokes two seed functions; compare arguments
  passed to both calls.
- shared callee mode: two seed functions invoke the same helper; compare
  arguments passed into that shared helper.

The goal is to distinguish same-owner bridges from shared-helper coincidences.
This script is read-only and never mutates IDA.
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
RW16 = os.environ.get("BINREV_S05_RW16", os.path.join(S05, "s05-rw16-lifecycle-bridge-trace.json"))
OUT = os.environ.get("BINREV_S05_RW17_OUT", os.path.join(S05, "s05-rw17-cross-function-arg-bridge.json"))

ARG_REGS = ["X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7"]
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


def func_by_start(start_s):
    start = parse_hex(start_s)
    return ida_funcs.get_func(start) if start is not None else None


def fixed_window(ea, before=8, after=6):
    start = max(0, ea - before * 4)
    return [
        {"ea": hx(cur), "mnem": mnem(cur), "text": dis(cur), "is_focus": cur == ea}
        for cur in range(start, ea + (after + 1) * 4, 4)
    ]


def code_refs_from_call(ea):
    if not mnem(ea).startswith("BL"):
        return []
    return [to for to in idautils.CodeRefsFrom(ea, 0)]


def call_targets(ea):
    return [{"ea": hx(to), "function": func_at(to), "text": dis(ea)} for to in code_refs_from_call(ea)]


def find_calls_to_target(f, target_start, limit=80):
    target = parse_hex(target_start)
    out = []
    if not f or target is None:
        return out
    for ea in idautils.FuncItems(f.start_ea):
        if not mnem(ea).startswith("BL"):
            continue
        targets = code_refs_from_call(ea)
        target_funcs = [ida_funcs.get_func(t) for t in targets]
        starts = {tf.start_ea for tf in target_funcs if tf}
        if target in starts or target in targets:
            out.append({"ea": hx(ea), "text": dis(ea), "targets": call_targets(ea), "window": fixed_window(ea)})
            if len(out) >= limit:
                break
    return out


def def_signature_for_insn(ea, reg, depth=0):
    text = dis(ea)
    mn = mnem(ea)
    up = text.upper()
    mems = parse_mem(text)

    if "TPIDR_EL2" in up and mn == "MRS":
        return {"kind": "sysreg", "value": "TPIDR_EL2", "ea": hx(ea), "text": text}

    if mn in {"ADRP", "ADR", "ADRL"}:
        return {"kind": "address_literal", "value": re.sub(r"\s+", " ", text.strip()), "ea": hx(ea), "text": text}

    if mn in {"MOV", "ORR"}:
        regs = [r for r in regs_in_text(up) if r != reg]
        imm = re.search(r"#(-?0X[0-9A-F]+|-?\d+)", up)
        if imm:
            return {"kind": "immediate", "value": imm.group(1), "ea": hx(ea), "text": text}
        if regs:
            return {"kind": "reg_copy", "value": regs[0], "ea": hx(ea), "text": text}

    if mn.startswith("LD") and mems:
        mem = mems[0]
        return {
            "kind": "memory_load",
            "base": mem.get("base"),
            "imm": None if mem.get("imm") is None else hex(int(mem["imm"])),
            "index_regs": mem.get("index_regs", []),
            "ea": hx(ea),
            "text": text,
        }

    if mn in {"ADD", "SUB", "AND", "EOR", "LSL", "LSR", "SXTW", "UXTW"}:
        regs = [r for r in regs_in_text(up) if r != reg]
        imm = re.search(r"#([A-Z0-9_@.$+-]+)", up)
        return {
            "kind": "compute",
            "op": mn,
            "regs": regs,
            "imm": imm.group(1) if imm else None,
            "text_key": re.sub(r"\s+", " ", text.strip()),
            "ea": hx(ea),
            "text": text,
        }

    return {"kind": "unknown_def", "ea": hx(ea), "text": text}


def trace_arg_root(call_ea, arg_reg, max_back=48):
    arg = norm_reg(arg_reg)
    f = ida_funcs.get_func(call_ea)
    if not f:
        return {"arg": arg, "root": {"kind": "no_function"}, "trace": []}
    cur_reg = arg
    trace = []
    searched = 0
    for ea in range(call_ea - 4, max(f.start_ea, call_ea - max_back * 4) - 1, -4):
        searched += 1
        text = dis(ea)
        dest = first_dest_reg(text)
        if dest != cur_reg:
            continue
        sig = def_signature_for_insn(ea, cur_reg)
        trace.append(sig)
        if sig["kind"] == "reg_copy":
            cur_reg = norm_reg(sig["value"])
            continue
        return {"arg": arg, "root": normalize_signature(sig), "trace": trace, "searched_insns": searched}
    return {"arg": arg, "root": {"kind": "incoming_arg_or_untraced", "reg": cur_reg}, "trace": trace, "searched_insns": searched}


def normalize_signature(sig):
    kind = sig.get("kind")
    if kind == "memory_load":
        return {"kind": kind, "base": sig.get("base"), "imm": sig.get("imm"), "index_regs": sig.get("index_regs", [])}
    if kind == "compute":
        return {
            "kind": kind,
            "op": sig.get("op"),
            "regs": sig.get("regs", []),
            "imm": sig.get("imm"),
            "text_key": sig.get("text_key") if not sig.get("regs") else None,
        }
    if kind in {"sysreg", "immediate", "address_literal"}:
        return {"kind": kind, "value": sig.get("value")}
    if kind == "reg_copy":
        return {"kind": kind, "value": norm_reg(sig.get("value"))}
    return {k: sig.get(k) for k in ("kind", "reg", "value") if k in sig}


def roots_equal(a, b):
    return normalize_for_compare(a) == normalize_for_compare(b)


def normalize_for_compare(root):
    if not root:
        return None
    kind = root.get("kind")
    if kind == "memory_load":
        return (kind, root.get("base"), root.get("imm"), tuple(root.get("index_regs", [])))
    if kind == "compute":
        # If a compute root has no surviving source register, it is often an
        # address materialization such as ADD X0, X0, #symbol@PAGEOFF. Keep the
        # text/symbol in the comparison; otherwise unrelated logging/string
        # arguments collapse into the same fake root.
        return (kind, root.get("op"), tuple(root.get("regs", [])), root.get("imm"), root.get("text_key") if not root.get("regs") else None)
    if kind in {"sysreg", "immediate", "address_literal", "incoming_arg_or_untraced"}:
        return (kind, root.get("value") or root.get("reg"))
    return tuple(sorted(root.items()))


def compare_arg_roots(call_a, call_b):
    roots_a = {r: trace_arg_root(parse_hex(call_a["ea"]), r) for r in ARG_REGS}
    roots_b = {r: trace_arg_root(parse_hex(call_b["ea"]), r) for r in ARG_REGS}
    matches = []
    for ra, va in roots_a.items():
        for rb, vb in roots_b.items():
            if roots_equal(va.get("root"), vb.get("root")):
                root = va.get("root")
                kind = root.get("kind")
                if kind not in {"incoming_arg_or_untraced", "unknown_def", "no_function"}:
                    matches.append({"arg_a": ra, "arg_b": rb, "root": root})
    same_arg_matches = [m for m in matches if m["arg_a"] == m["arg_b"]]
    score = len(same_arg_matches) * 3 + len(matches)
    if any(m["root"].get("kind") in {"memory_load", "sysreg", "address_literal", "compute"} for m in same_arg_matches):
        score += 3
    decision = "no_shared_argument_root"
    if score >= 6:
        decision = "strong_shared_argument_root_review"
    elif score > 0:
        decision = "weak_shared_argument_root_review"
    return {
        "call_a": call_a,
        "call_b": call_b,
        "roots_a": roots_a,
        "roots_b": roots_b,
        "matches": matches,
        "same_arg_matches": same_arg_matches,
        "score": score,
        "decision": decision,
    }


def analyze_shared_caller(pair, caller_start):
    f = func_by_start(caller_start)
    calls_a = find_calls_to_target(f, pair["a"]["start"])
    calls_b = find_calls_to_target(f, pair["b"]["start"])
    comparisons = []
    for ca in calls_a[:8]:
        for cb in calls_b[:8]:
            comparisons.append(compare_arg_roots(ca, cb))
    comparisons.sort(key=lambda x: -x["score"])
    return {
        "mode": "shared_caller",
        "caller": func_at(f.start_ea) if f else {"start": caller_start},
        "a": pair["a"],
        "b": pair["b"],
        "calls_to_a": calls_a,
        "calls_to_b": calls_b,
        "comparisons": comparisons[:20],
        "best_score": comparisons[0]["score"] if comparisons else 0,
        "best_decision": comparisons[0]["decision"] if comparisons else "no_call_pair",
    }


def analyze_shared_callee(pair, callee_start):
    fa = func_by_start(pair["a"]["start"])
    fb = func_by_start(pair["b"]["start"])
    calls_a = find_calls_to_target(fa, callee_start)
    calls_b = find_calls_to_target(fb, callee_start)
    comparisons = []
    for ca in calls_a[:8]:
        for cb in calls_b[:8]:
            comparisons.append(compare_arg_roots(ca, cb))
    comparisons.sort(key=lambda x: -x["score"])
    return {
        "mode": "shared_callee",
        "callee": func_at(parse_hex(callee_start)) if parse_hex(callee_start) is not None else {"start": callee_start},
        "a": pair["a"],
        "b": pair["b"],
        "calls_from_a": calls_a,
        "calls_from_b": calls_b,
        "comparisons": comparisons[:20],
        "best_score": comparisons[0]["score"] if comparisons else 0,
        "best_decision": comparisons[0]["decision"] if comparisons else "no_call_pair",
    }


def main():
    with open(RW16, "r", encoding="utf-8") as fp:
        rw16 = json.load(fp)

    bridges = []
    for pair in rw16.get("shared_bridge_pairs", []):
        for caller in pair.get("shared_callers", []):
            bridges.append(analyze_shared_caller(pair, caller))
        for callee in pair.get("shared_callees", []):
            bridges.append(analyze_shared_callee(pair, callee))

    bridges.sort(key=lambda x: -x.get("best_score", 0))
    strong = [x for x in bridges if x.get("best_decision") == "strong_shared_argument_root_review"]
    weak = [x for x in bridges if x.get("best_decision") == "weak_shared_argument_root_review"]

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw17_cross_function_arg_bridge.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW17",
        "policy": "read_only_ida_trace",
        "input_artifact": RW16,
        "bridge_analyses": bridges,
        "summary": {
            "bridge_analysis_count": len(bridges),
            "strong_shared_argument_root_count": len(strong),
            "weak_shared_argument_root_count": len(weak),
            "best_bridge_score": bridges[0]["best_score"] if bridges else 0,
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_cross_function_arg_bridge",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW17 compares cross-function argument roots for shared bridge pairs. Strong shared roots remain review-only until tied to VM/vCPU/Stage-2 resource identity.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW17 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
