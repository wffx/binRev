"""IDA-side S05-RW16 lifecycle bridge trace.

Consumes RW15 TPIDR-confirmed writer/clearer candidates and RW4 lifecycle
summaries. For each seed function it gathers caller/callee context, nearby
calls around writer events, RW4 lifecycle overlap, and shared bridge functions.

This is evidence-only and never mutates IDA.
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
RW15 = os.environ.get("BINREV_S05_RW15", os.path.join(S05, "s05-rw15-tpidr-writer-lifecycle-trace.json"))
RW4 = os.environ.get("BINREV_S05_RW4", os.path.join(S05, "s05-rw4-lifecycle-edges.json"))
OUT = os.environ.get("BINREV_S05_RW16_OUT", os.path.join(S05, "s05-rw16-lifecycle-bridge-trace.json"))

SYSREG_PATTERNS = [
    "TPIDR_EL2",
    "VTTBR_EL2",
    "VTCR_EL2",
    "HCR_EL2",
    "SCTLR_EL2",
    "TCR_EL2",
    "VBAR_EL2",
    "ESR_EL2",
    "FAR_EL2",
    "HPFAR_EL2",
    "ICH_",
    "ICC_",
]

LIFECYCLE_WORDS = [
    "init",
    "setup",
    "start",
    "stop",
    "pause",
    "resume",
    "destroy",
    "free",
    "alloc",
    "clear",
    "reset",
    "teardown",
    "switch",
    "schedule",
    "vcpu",
    "cpu",
    "domain",
    "vm",
    "grant",
    "irq",
    "gic",
]


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


def call_targets(ea):
    txt = dis(ea).strip().upper()
    if not txt.startswith("BL"):
        return []
    out = []
    for to in idautils.CodeRefsFrom(ea, 0):
        out.append({"ea": hx(to), "function": func_at(to), "text": dis(ea)})
    return out


def collect_callers(start_ea, limit=120):
    out = []
    seen = set()
    for ref in idautils.CodeRefsTo(start_ea, 0):
        f = ida_funcs.get_func(ref)
        if not f:
            continue
        key = (f.start_ea, ref)
        if key in seen:
            continue
        seen.add(key)
        out.append({"callsite": hx(ref), "function": func_at(f.start_ea), "text": dis(ref), "window": fixed_window(ref, 6, 8)})
        if len(out) >= limit:
            break
    return out


def collect_callees(f, limit=160):
    out = []
    seen = set()
    if not f:
        return out
    for ea in idautils.FuncItems(f.start_ea):
        if not mnem(ea).startswith("BL"):
            continue
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


def fixed_window(ea, before=8, after=10):
    start = max(0, ea - before * 4)
    return [
        {"ea": hx(cur), "mnem": mnem(cur), "text": dis(cur), "is_focus": cur == ea}
        for cur in range(start, ea + (after + 1) * 4, 4)
    ]


def collect_strings(f, limit=60):
    out = []
    if not f:
        return out
    try:
        string_map = {int(s.ea): str(s) for s in idautils.Strings()}
    except Exception:
        string_map = {}
    for ea in idautils.FuncItems(f.start_ea):
        for dr in idautils.DataRefsFrom(ea):
            if dr in string_map:
                out.append({"from": hx(ea), "string_ea": hx(dr), "text": string_map[dr]})
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
        up = text.upper()
        for pat in SYSREG_PATTERNS:
            if pat in up:
                counts[pat] = counts.get(pat, 0) + 1
                if len(samples) < 80:
                    samples.append({"ea": hx(ea), "pattern": pat, "text": text})
    return {"counts": counts, "samples": samples}


def classify_window(window):
    text = "\n".join(x.get("text", "").upper() for x in window)
    tags = []
    if re.search(r"\bSTR\w*\s+[XW]ZR\s*,", text) or re.search(r"\bSTP\s+(?:[XW]ZR|[XW]\d+)\s*,\s*(?:[XW]ZR|[XW]\d+)\s*,", text) or re.search(r"\bMOV\s+[XW]\d+,\s*#0\b", text):
        tags.append("clear_or_zero")
    if re.search(r"\bSTP?\b|\bSTR", text):
        tags.append("field_write")
    if re.search(r"\bLDP?\b|\bLDR", text):
        tags.append("field_read")
    if re.search(r"\bBLR?\b", text):
        tags.append("calls_nearby")
    if re.search(r"\bCBZ\b|\bCBNZ\b|\bB\.", text):
        tags.append("branch_or_state_check")
    if "TPIDR_EL2" in text:
        tags.append("tpidr_context")
    return tags or ["unclassified"]


def lifecycle_words_from_strings(strings):
    hits = []
    for s in strings:
        low = s.get("text", "").lower()
        words = [w for w in LIFECYCLE_WORDS if w in low]
        if words:
            hits.append({"string": s, "words": words})
    return hits


def rw4_index(rw4):
    by_start = {}
    for item in rw4.get("function_lifecycle_summaries", []):
        fn = item.get("function") or item.get("target") or {}
        start = fn.get("start") or item.get("start")
        if start:
            by_start[start.lower()] = item
    # Older RW4 artifacts may use `targets` plus summaries; index targets too.
    for item in rw4.get("targets", []):
        start = (item.get("function") or item).get("start") if isinstance(item, dict) else None
        if start and start.lower() not in by_start:
            by_start[start.lower()] = item
    return by_start


def extract_seed_functions(rw15):
    seeds = {}
    for fn in rw15.get("tpidr_confirmed_functions", []):
        if fn.get("derived_write_count", 0) <= 0:
            continue
        f = fn.get("function") or {}
        start = f.get("start")
        if not start:
            continue
        rec = seeds.setdefault(start.lower(), {"function": f, "rw15": fn, "offsets": set(), "write_events": []})
        for ev in fn.get("derived_events", []):
            if ev.get("kind") in {"write", "atomic"}:
                imm = ev.get("mem", {}).get("imm")
                if imm is not None:
                    rec["offsets"].add(hex(int(imm)))
                rec["write_events"].append(ev)
    for rec in seeds.values():
        rec["offsets"] = sorted(rec["offsets"])
    return list(seeds.values())


def event_bridge_context(ev):
    ea = parse_hex(ev.get("ea"))
    if ea is None:
        return {}
    win = fixed_window(ea, 8, 10)
    nearby_calls = []
    for item in win:
        cur = parse_hex(item.get("ea"))
        if cur is not None and mnem(cur).startswith("BL"):
            nearby_calls.append({"ea": item.get("ea"), "text": item.get("text"), "targets": call_targets(cur)})
    return {"event": ev, "window_tags": classify_window(win), "nearby_calls": nearby_calls, "window": win}


def summarize_seed(seed, rw4_by_start):
    f = func_by_start(seed["function"].get("start"))
    callers = collect_callers(f.start_ea, limit=80) if f else []
    callees = collect_callees(f, limit=120) if f else []
    strings = collect_strings(f, limit=80) if f else []
    sysregs = collect_sysregs(f) if f else {"counts": {}, "samples": []}
    rw4_hit = rw4_by_start.get((seed["function"].get("start") or "").lower())

    write_contexts = [event_bridge_context(ev) for ev in seed.get("write_events", [])[:20]]
    tags = {}
    for ctx in write_contexts:
        for tag in ctx.get("window_tags", []):
            tags[tag] = tags.get(tag, 0) + 1

    caller_starts = {c.get("function", {}).get("start") for c in callers}
    callee_starts = {c.get("target", {}).get("start") for c in callees}

    score = 0
    reasons = []
    if seed.get("offsets"):
        score += 1
        reasons.append("has_tpidr_confirmed_writer_offsets")
    if tags.get("clear_or_zero"):
        score += 2
        reasons.append("has_clear_or_zero_write_context")
    if rw4_hit:
        score += 2
        reasons.append("function_in_rw4_lifecycle_summary")
    if callers:
        score += 1
        reasons.append("has_callers_for_bridge")
    if callees:
        score += 1
        reasons.append("has_callees_for_bridge")
    if lifecycle_words_from_strings(strings):
        score += 1
        reasons.append("strings_have_lifecycle_words")
    if sysregs.get("counts"):
        score += 1
        reasons.append("has_arch_sysreg_context")

    decision = "review_required_lifecycle_bridge_candidate"
    if score >= 6 and (rw4_hit or tags.get("clear_or_zero")):
        decision = "strong_review_lifecycle_bridge_candidate"

    return {
        "function": func_at(f.start_ea) if f else seed.get("function"),
        "offsets": seed.get("offsets", []),
        "rw15_write_event_count": len(seed.get("write_events", [])),
        "rw15_write_contexts": write_contexts,
        "callers": callers,
        "callees": callees,
        "caller_starts": sorted(x for x in caller_starts if x),
        "callee_starts": sorted(x for x in callee_starts if x),
        "sysregs": sysregs,
        "strings": strings[:40],
        "lifecycle_string_hits": lifecycle_words_from_strings(strings)[:20],
        "rw4_lifecycle_hit": rw4_hit,
        "local_tag_counts": tags,
        "bridge_score": score,
        "bridge_reasons": reasons,
        "decision": decision,
    }


def compute_shared_bridges(seed_summaries):
    pairs = []
    for i, a in enumerate(seed_summaries):
        for b in seed_summaries[i + 1 :]:
            shared_callers = sorted(set(a.get("caller_starts", [])).intersection(b.get("caller_starts", [])))
            shared_callees = sorted(set(a.get("callee_starts", [])).intersection(b.get("callee_starts", [])))
            if shared_callers or shared_callees:
                pairs.append(
                    {
                        "a": a.get("function"),
                        "b": b.get("function"),
                        "shared_callers": shared_callers[:40],
                        "shared_callees": shared_callees[:40],
                        "score": len(shared_callers) * 2 + len(shared_callees),
                    }
                )
    pairs.sort(key=lambda x: (-x["score"], x["a"]["start"], x["b"]["start"]))
    return pairs


def main():
    with open(RW15, "r", encoding="utf-8") as fp:
        rw15 = json.load(fp)
    with open(RW4, "r", encoding="utf-8") as fp:
        rw4 = json.load(fp)

    seeds = extract_seed_functions(rw15)
    rw4_by_start = rw4_index(rw4)
    summaries = [summarize_seed(seed, rw4_by_start) for seed in seeds]
    summaries.sort(key=lambda x: (-x.get("bridge_score", 0), x.get("function", {}).get("start", "")))
    shared = compute_shared_bridges(summaries)

    strong = [x for x in summaries if x.get("decision") == "strong_review_lifecycle_bridge_candidate"]

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/ida_s05_rw16_lifecycle_bridge_trace.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW16",
        "policy": "read_only_ida_trace",
        "input_artifacts": [RW15, RW4],
        "seed_function_count": len(seeds),
        "seed_summaries": summaries,
        "shared_bridge_pairs": shared[:80],
        "summary": {
            "seed_function_count": len(seeds),
            "strong_bridge_candidate_count": len(strong),
            "rw4_lifecycle_hit_count": sum(1 for x in summaries if x.get("rw4_lifecycle_hit")),
            "clear_or_zero_context_count": sum(1 for x in summaries if x.get("local_tag_counts", {}).get("clear_or_zero")),
            "shared_bridge_pair_count": len(shared),
            "production_ownership_ready_count": 0,
        },
        "decision": {
            "status": "review_required_lifecycle_bridge_trace",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW16 bridges TPIDR writer/clearer candidates to caller/callee/lifecycle context, but keeps them review-only until object/resource identity is proven.",
        },
    }

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    ida_kernwin.msg("S05-RW16 wrote %s\n" % OUT)


if __name__ == "__main__":
    main()
