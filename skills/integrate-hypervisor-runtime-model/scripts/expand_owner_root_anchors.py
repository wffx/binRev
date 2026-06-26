"""Expand S05 owner-root continuation queues with existing S05 evidence.

This script consumes:

- S05-RW9 owner-root continuation plan
- S05-RW2 dataflow slices
- S05-RW3 owner/base traces
- S05-RW6 owner/root matches

It produces S05-RW10 root-anchor expansion evidence. The output still does not
promote ownership links; it ranks which anchor families should be traced next.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
GLOBAL_RE = re.compile(r"\b(?:off|qword|dword|word|byte|unk)_[0-9A-Fa-f]+")
TPIDR_RE = re.compile(r"TPIDR_EL2", re.I)


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def hex_int(s):
    if not s:
        return None
    try:
        return int(str(s), 16)
    except Exception:
        return None


def func_start(row):
    f = row.get("function") or {}
    return f.get("start")


def root_names(sig: str):
    return GLOBAL_RE.findall(sig or "")


def contains_global(obj, name: str) -> bool:
    return name and name in json.dumps(obj, ensure_ascii=False)


def in_func(addr: str, fn: dict) -> bool:
    a = hex_int(addr)
    s = hex_int(fn.get("start"))
    e = hex_int(fn.get("end"))
    return a is not None and s is not None and e is not None and s <= a < e


def summarize_tpidr_support(rw9, rw2, rw3):
    percpu_queue = rw9.get("queues", {}).get("percpu_state_anchor", [])
    tpidr_funcs = rw3.get("tpidr_base_traces", [])
    tpidr_slices = rw2.get("tpidr_slices", [])

    # Index function starts for quick matching.
    by_func = {func_start(r): r for r in tpidr_funcs if func_start(r)}
    slice_by_func = {func_start(r): r for r in tpidr_slices if func_start(r)}

    support = []
    caller_hits = Counter()
    target_hits = Counter()
    for q in percpu_queue:
        callers = [q.get("setup_caller"), q.get("teardown_caller")]
        targets = [q.get("setup_target"), q.get("teardown_target")]
        matched = []
        for row in tpidr_funcs:
            fn = row.get("function", {})
            if fn.get("start") in callers + targets or any(in_func(c, fn) for c in callers if c):
                matched.append(row)
        for c in callers:
            if c:
                caller_hits[c] += 1
        for t in targets:
            if t:
                target_hits[t] += 1
        support.append(
            {
                "queue_item": q,
                "matched_tpidr_trace_functions": [
                    {
                        "function": m.get("function"),
                        "event_count": m.get("event_count"),
                        "role": m.get("role"),
                        "base_root_class_histogram": m.get("base_root_class_histogram"),
                        "base_reg_histogram": m.get("base_reg_histogram"),
                        "string_ref_count": len(m.get("string_refs", [])),
                    }
                    for m in matched
                ],
                "match_count": len(matched),
                "expansion_status": "percpu_state_seed_review_only",
            }
        )

    ranked_trace_functions = sorted(
        [
            {
                "function": row.get("function"),
                "event_count": row.get("event_count"),
                "base_root_class_histogram": row.get("base_root_class_histogram"),
                "role": row.get("role"),
                "slice_available": func_start(row) in slice_by_func,
            }
            for row in tpidr_funcs
        ],
        key=lambda r: r.get("event_count") or 0,
        reverse=True,
    )
    return {
        "queue_count": len(percpu_queue),
        "caller_hits": [{"caller": k, "count": v} for k, v in caller_hits.most_common()],
        "target_hits": [{"target": k, "count": v} for k, v in target_hits.most_common()],
        "queue_support": support,
        "ranked_tpidr_trace_functions": ranked_trace_functions[:12],
        "decision": {
            "status": "review_only_percpu_state_anchor",
            "reason": "TPIDR_EL2 anchors repeatedly support per-CPU/current-state seeds, but no VM/Stage-2 owner identity is proven.",
        },
    }


def summarize_global_support(rw9, rw3, rw6):
    global_queue = rw9.get("queues", {}).get("global_state_anchor", [])
    names = Counter()
    for q in global_queue:
        for sig in q.get("common_argument_root_signatures", []):
            for n in root_names(sig):
                names[n] += 1

    stage2_traces = rw3.get("stage2_owner_traces", [])
    weak_matches = rw6.get("weak_matches", [])
    exact_matches = rw6.get("exact_root_matches", [])

    globals_out = []
    for name, count in names.most_common():
        trace_hits = [r for r in stage2_traces if contains_global(r, name)]
        weak_hits = [r for r in weak_matches if contains_global(r, name)]
        exact_hits = [r for r in exact_matches if contains_global(r, name)]
        callers = Counter()
        targets = Counter()
        for r in trace_hits:
            for c in r.get("callers", []):
                if isinstance(c, dict):
                    if c.get("caller"):
                        callers[str(c.get("caller"))] += 1
                    if c.get("callsite"):
                        callers[str(c.get("callsite"))] += 1
            fn = r.get("function")
            if isinstance(fn, dict) and fn.get("start"):
                targets[fn["start"]] += 1
        globals_out.append(
            {
                "global_anchor": name,
                "rw9_count": count,
                "stage2_owner_trace_hit_count": len(trace_hits),
                "weak_owner_root_match_hit_count": len(weak_hits),
                "exact_owner_root_match_hit_count": len(exact_hits),
                "top_related_callers_or_callsites": [{"addr": k, "count": v} for k, v in callers.most_common(8)],
                "top_related_targets": [{"target": k, "count": v} for k, v in targets.most_common(8)],
                "expansion_status": "global_state_seed_review_only",
                "next_action": "Trace all xrefs and writes to decide whether this is service-global state, constant/config, or per-CPU table root.",
            }
        )

    return {
        "queue_count": len(global_queue),
        "global_anchor_count": len(globals_out),
        "anchors": globals_out,
        "decision": {
            "status": "review_only_global_state_anchor",
            "reason": "Global anchors can seed state identity analysis but do not prove object ownership without write/lifetime/resource closure.",
        },
    }


def summarize_stack_support(rw9):
    queue = rw9.get("queues", {}).get("stack_parent_trace", [])
    out = []
    for q in queue:
        out.append(
            {
                "queue_item": q,
                "expansion_status": "requires_interprocedural_parent_trace",
                "next_action": "Recover the caller's incoming argument/root and repeat classification; stack reload alone is not an owner identity.",
            }
        )
    return {
        "queue_count": len(queue),
        "items": out,
        "decision": {
            "status": "blocked_until_parent_argument_trace",
            "reason": "Stack-local roots require a caller/parent trace before object identity can be evaluated.",
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rw9", required=True, type=Path)
    ap.add_argument("--rw2", required=True, type=Path)
    ap.add_argument("--rw3", required=True, type=Path)
    ap.add_argument("--rw6", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--iteration-id", default="S05-RW10")
    args = ap.parse_args()

    rw9 = load(args.rw9)
    rw2 = load(args.rw2)
    rw3 = load(args.rw3)
    rw6 = load(args.rw6)

    percpu = summarize_tpidr_support(rw9, rw2, rw3)
    glob = summarize_global_support(rw9, rw3, rw6)
    stack = summarize_stack_support(rw9)

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/expand_owner_root_anchors.py",
        "stage_id": "S05",
        "iteration_id": args.iteration_id,
        "input_artifacts": {
            "rw9": str(args.rw9),
            "rw2": str(args.rw2),
            "rw3": str(args.rw3),
            "rw6": str(args.rw6),
        },
        "summary": {
            "percpu_state_anchor_queue_count": percpu["queue_count"],
            "global_state_anchor_queue_count": glob["queue_count"],
            "stack_parent_trace_queue_count": stack["queue_count"],
            "production_ownership_ready_count": 0,
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
        },
        "percpu_state_expansion": percpu,
        "global_state_expansion": glob,
        "stack_parent_expansion": stack,
        "decision": {
            "status": "review_required_anchor_expansion",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW10 expands root anchors into per-CPU/global/stack evidence families but still lacks owner lifetime and resource identity closure.",
            "next_iteration": "S05-RW11 should trace writes/xrefs for the dominant global anchors and parent arguments for stack-local roots, or use IDA to expand TPIDR offset-family writes.",
        },
    }
    write(args.output, result)


if __name__ == "__main__":
    main()
