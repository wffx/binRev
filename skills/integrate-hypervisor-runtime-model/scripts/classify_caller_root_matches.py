"""Classify S05 caller-argument root matches before ownership promotion.

Input is a caller-argument propagation artifact, normally
`S05/s05-rw7-caller-arg-propagation.json`. The output separates matches into:

- object_like: may continue to lifecycle/VMID/resource checks
- service_local: same helper/caller or helper-rooted match, review-only
- global_or_constant: global address literal or named constant roots, review-only
- stack_local: stack reload roots, review-only
- ambiguous: insufficient root evidence, review-only

The script is intentionally conservative. It never creates production
ownership links; it only emits classification evidence for the integration
skill to consume.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


GLOBAL_NAME_RE = re.compile(r"\b(?:off|qword|dword|word|byte|unk|loc|a[A-Z0-9_])_[0-9A-Fa-f]+")


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def root_class(sig: str) -> str:
    low = sig.lower()
    if low.startswith("stack_reload:") or "[sp" in low:
        return "stack_local"
    if low.startswith("address_literal:") or "@page" in low or GLOBAL_NAME_RE.search(sig):
        return "global_or_constant"
    if low.startswith("sysreg:"):
        return "system_state"
    if low.startswith("memory_load:"):
        if "[sp" in low or GLOBAL_NAME_RE.search(sig):
            return "stack_local" if "[sp" in low else "global_or_constant"
        return "object_like"
    if low.startswith("compute:"):
        return "ambiguous"
    return "ambiguous"


def match_bucket(row) -> tuple[str, list[str]]:
    reasons = list(row.get("reasons", []))
    roots = list(row.get("common_argument_root_signatures", []))
    setup = row.get("setup", {})
    teardown = row.get("teardown", {})
    setup_target = setup.get("target", {}).get("start")
    teardown_target = teardown.get("target", {}).get("start")
    setup_callsite = setup.get("callsite", {}).get("callsite")
    teardown_callsite = teardown.get("callsite", {}).get("callsite")
    setup_caller = setup.get("callsite", {}).get("caller", {}).get("start")
    teardown_caller = teardown.get("callsite", {}).get("caller", {}).get("start")

    classes = sorted({root_class(sig) for sig in roots})
    notes = []
    if setup_target == teardown_target or setup_callsite == teardown_callsite or setup_caller == teardown_caller:
        notes.append("same_helper_or_same_caller")
        return "service_local", notes + classes
    if not roots:
        return "ambiguous", ["no_common_root"]
    if "global_or_constant" in classes:
        return "global_or_constant", classes
    if "stack_local" in classes:
        return "stack_local", classes
    if classes and all(cls == "object_like" for cls in classes):
        return "object_like", classes
    if "object_like" in classes:
        return "ambiguous", classes
    return "ambiguous", classes or ["unclassified"]


def compact(row):
    bucket, notes = match_bucket(row)
    setup = row.get("setup", {})
    teardown = row.get("teardown", {})
    return {
        "bucket": bucket,
        "classification_notes": notes,
        "score": row.get("score"),
        "reasons": row.get("reasons", []),
        "setup_target": setup.get("target", {}).get("start"),
        "setup_callsite": setup.get("callsite", {}).get("callsite"),
        "setup_caller": setup.get("callsite", {}).get("caller", {}).get("start"),
        "teardown_target": teardown.get("target", {}).get("start"),
        "teardown_callsite": teardown.get("callsite", {}).get("callsite"),
        "teardown_caller": teardown.get("callsite", {}).get("caller", {}).get("start"),
        "common_argument_root_signatures": row.get("common_argument_root_signatures", []),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--stage-id", default="S05")
    ap.add_argument("--iteration-id", default="S05-RW8")
    args = ap.parse_args()

    data = load_json(args.input)
    rows = [compact(row) for row in data.get("exact_argument_matches", [])]
    rows += [compact(row) for row in data.get("weak_same_caller_matches", [])]

    buckets = {
        "object_like": [],
        "service_local": [],
        "global_or_constant": [],
        "stack_local": [],
        "ambiguous": [],
    }
    for row in rows:
        buckets[row["bucket"]].append(row)

    summary = {
        "input_match_count": len(rows),
        "object_like_count": len(buckets["object_like"]),
        "service_local_count": len(buckets["service_local"]),
        "global_or_constant_count": len(buckets["global_or_constant"]),
        "stack_local_count": len(buckets["stack_local"]),
        "ambiguous_count": len(buckets["ambiguous"]),
        "production_ownership_ready_count": 0,
    }
    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/classify_caller_root_matches.py",
        "stage_id": args.stage_id,
        "iteration_id": args.iteration_id,
        "input_artifact": str(args.input),
        "summary": summary,
        "decision": {
            "s06_readiness": "blocked_until_s05_owner_lifetime_closure",
            "reason": "Root classification produced no production-ready ownership links; object-like matches still require lifecycle, VMID, and resource identity checks.",
        },
        "buckets": buckets,
    }
    write_json(args.output, result)


if __name__ == "__main__":
    main()
