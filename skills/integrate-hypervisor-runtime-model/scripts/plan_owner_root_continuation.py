"""Build an S05 continuation plan after caller-root classification.

Input is normally `S05/s05-rw8-root-classification.json`.

The script does not promote ownership. It converts non-object-like root
classification buckets into explicit next-action queues:

- helper_self_loop: same target/callsite/caller, likely helper-local evidence
- global_state_anchor: global/constant roots that may seed service-global state
- percpu_state_anchor: TPIDR_EL2/system-state roots that may seed per-CPU state
- stack_parent_trace: stack roots requiring caller/upstream argument tracing
- ambiguous_backtrace: roots that need deeper backward slicing

These queues give S05 a concrete rework path without pretending S06-ready
object ownership exists.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def roots(row):
    return list(row.get("common_argument_root_signatures", []))


def has_sysreg(row):
    return any(sig.lower().startswith("sysreg:") or "tpidr_el2" in sig.lower() for sig in roots(row))


def has_stack(row):
    return any(sig.lower().startswith("stack_reload:") or "[sp" in sig.lower() for sig in roots(row))


def has_global(row):
    return any(
        sig.lower().startswith("address_literal:")
        or "@page" in sig.lower()
        or any(prefix in sig for prefix in ("off_", "qword_", "dword_", "word_", "byte_", "unk_"))
        for sig in roots(row)
    )


def same_context(row):
    return (
        row.get("setup_target") == row.get("teardown_target")
        or row.get("setup_callsite") == row.get("teardown_callsite")
        or row.get("setup_caller") == row.get("teardown_caller")
    )


def compact(row):
    return {
        "bucket": row.get("bucket"),
        "score": row.get("score"),
        "setup_target": row.get("setup_target"),
        "setup_callsite": row.get("setup_callsite"),
        "setup_caller": row.get("setup_caller"),
        "teardown_target": row.get("teardown_target"),
        "teardown_callsite": row.get("teardown_callsite"),
        "teardown_caller": row.get("teardown_caller"),
        "classification_notes": row.get("classification_notes", []),
        "common_argument_root_signatures": roots(row),
    }


def queue_record(row, reason, next_action, confidence="review_only"):
    rec = compact(row)
    rec.update(
        {
            "reason": reason,
            "next_action": next_action,
            "promotion_status": confidence,
        }
    )
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--stage-id", default="S05")
    ap.add_argument("--iteration-id", default="S05-RW9")
    args = ap.parse_args()

    data = load_json(args.input)
    buckets = data.get("buckets", {})
    queues = {
        "helper_self_loop": [],
        "global_state_anchor": [],
        "percpu_state_anchor": [],
        "stack_parent_trace": [],
        "ambiguous_backtrace": [],
    }

    all_rows = []
    for name, rows in buckets.items():
        for row in rows:
            row = dict(row)
            row.setdefault("bucket", name)
            all_rows.append(row)

    for row in all_rows:
        if same_context(row):
            queues["helper_self_loop"].append(
                queue_record(
                    row,
                    "setup and teardown evidence share the same helper/caller context",
                    "Do not promote to ownership; inspect caller's parent/root object and classify helper role.",
                )
            )
            continue
        if has_global(row):
            queues["global_state_anchor"].append(
                queue_record(
                    row,
                    "root is a global/address literal/constant",
                    "Trace all xrefs to the global and decide whether it is service-global state, constant table, or config anchor.",
                )
            )
            continue
        if has_sysreg(row):
            queues["percpu_state_anchor"].append(
                queue_record(
                    row,
                    "root is derived from TPIDR_EL2 or system state",
                    "Trace TPIDR-indexed offset families and connect them to CPU/per-CPU objects before any VM/Stage-2 ownership claim.",
                )
            )
            continue
        if has_stack(row):
            queues["stack_parent_trace"].append(
                queue_record(
                    row,
                    "root is stack-local",
                    "Run an interprocedural parent-argument trace from the caller to recover the original object root.",
                )
            )
            continue
        queues["ambiguous_backtrace"].append(
            queue_record(
                row,
                "root evidence is insufficient or mixed",
                "Run deeper backward slicing and keep the match review-only until an object root survives lifecycle/resource checks.",
            )
        )

    root_counter = Counter()
    target_counter = Counter()
    caller_counter = Counter()
    for row in all_rows:
        for sig in roots(row):
            root_counter[sig] += 1
        if row.get("setup_target"):
            target_counter[row["setup_target"]] += 1
        if row.get("teardown_target"):
            target_counter[row["teardown_target"]] += 1
        if row.get("setup_caller"):
            caller_counter[row["setup_caller"]] += 1
        if row.get("teardown_caller"):
            caller_counter[row["teardown_caller"]] += 1

    queue_counts = {k: len(v) for k, v in queues.items()}
    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/plan_owner_root_continuation.py",
        "stage_id": args.stage_id,
        "iteration_id": args.iteration_id,
        "input_artifact": str(args.input),
        "summary": {
            "input_match_count": len(all_rows),
            "queue_counts": queue_counts,
            "production_ownership_ready_count": 0,
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
        },
        "dominant_roots": [{"root": k, "count": v} for k, v in root_counter.most_common(12)],
        "dominant_targets": [{"target": k, "count": v} for k, v in target_counter.most_common(12)],
        "dominant_callers": [{"caller": k, "count": v} for k, v in caller_counter.most_common(12)],
        "queues": queues,
        "decision": {
            "status": "review_required_root_continuation_plan",
            "s06_readiness": "blocked_until_s05_object_like_owner_root",
            "reason": "RW9 creates concrete rework queues, but still finds no object-like owner root suitable for S06 production modeling.",
            "next_skill_focus": [
                "recover parent object roots for stack-local/service-local helpers",
                "trace global state anchors and decide service-global vs constant/config",
                "trace TPIDR_EL2 offset families to per-CPU state before VM/Stage-2 ownership promotion",
            ],
        },
    }
    write_json(args.output, result)


if __name__ == "__main__":
    main()
