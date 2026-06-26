"""S05-RW18 convergence gate.

This local script consumes S05 review artifacts and decides whether the S05
runtime object model can produce production ownership links for S06. It does
not use IDA and does not mutate IDB state.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


ROOT = Path(os.environ.get("BINREV_ROOT", r"F:\AI\codexProject\binRev"))
S05 = ROOT / "cases" / "xen_arm64-778090a1" / "stages" / "S05"
OUT = Path(os.environ.get("BINREV_S05_RW18_OUT", str(S05 / "s05-rw18-convergence-gate.json")))


def load(name, default=None):
    path = S05 / name
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def summary_of(obj):
    if not isinstance(obj, dict):
        return {}
    return obj.get("summary") or {}


def main():
    runtime = load("runtime-object-model.json", {})
    rw8 = load("s05-rw8-root-classification.json", {})
    rw13 = load("s05-rw13-global-value-source-trace.json", {})
    rw14 = load("s05-rw14-tpidr-offset-family-trace.json", {})
    rw15 = load("s05-rw15-tpidr-writer-lifecycle-trace.json", {})
    rw16 = load("s05-rw16-lifecycle-bridge-trace.json", {})
    rw17 = load("s05-rw17-cross-function-arg-bridge.json", {})

    ownership_links = runtime.get("ownership_links") or []
    review_links = runtime.get("review_only_links") or []
    blocking_unknowns = runtime.get("blocking_unknowns") or []

    rw8_summary = summary_of(rw8)
    rw13_summary = summary_of(rw13)
    rw14_summary = summary_of(rw14)
    rw15_summary = summary_of(rw15)
    rw16_summary = summary_of(rw16)
    rw17_summary = summary_of(rw17)

    production_counts = {
        "runtime_ownership_links": len(ownership_links),
        "rw13_production_ownership_ready_count": rw13_summary.get("production_ownership_ready_count", 0),
        "rw14_production_ownership_ready_count": rw14_summary.get("production_ownership_ready_count", 0),
        "rw15_production_ownership_ready_count": rw15_summary.get("production_ownership_ready_count", 0),
        "rw16_production_ownership_ready_count": rw16_summary.get("production_ownership_ready_count", 0),
        "rw17_production_ownership_ready_count": rw17_summary.get("production_ownership_ready_count", 0),
    }
    production_ready_total = sum(int(v or 0) for v in production_counts.values())

    positive_review_evidence = [
        {
            "artifact": "s05-rw14-tpidr-offset-family-trace.json",
            "finding": "TPIDR-derived slot/offset families",
            "summary": rw14_summary,
            "promotion_status": "review_only_field_family_seed",
        },
        {
            "artifact": "s05-rw15-tpidr-writer-lifecycle-trace.json",
            "finding": "TPIDR-confirmed writer/clearer candidates for offsets 0x18 and 0x10",
            "summary": rw15_summary,
            "promotion_status": "review_only_lifecycle_candidate",
        },
        {
            "artifact": "s05-rw16-lifecycle-bridge-trace.json",
            "finding": "caller/callee/local lifecycle bridge candidates",
            "summary": rw16_summary,
            "promotion_status": "review_only_bridge_candidate",
        },
        {
            "artifact": "s05-rw17-cross-function-arg-bridge.json",
            "finding": "one strong shared caller argument bridge rooted in static/per-CPU context",
            "summary": rw17_summary,
            "promotion_status": "review_only_context_bridge",
        },
    ]

    negative_findings = [
        {
            "artifact": "s05-rw8-root-classification.json",
            "finding": "no object-like root suitable for S06 production ownership",
            "summary": rw8_summary,
        },
        {
            "artifact": "s05-rw13-global-value-source-trace.json",
            "finding": "dword_96000 converged to scalar/count-like global, not object owner",
            "summary": rw13_summary,
        },
        {
            "artifact": "s05-rw17-cross-function-arg-bridge.json",
            "finding": "best bridge shares static/per-CPU roots, not VM/vCPU/Stage-2 resource identity",
            "summary": rw17_summary,
        },
    ]

    if production_ready_total > 0:
        status = "accepted_with_review_required_links"
        s06_readiness = "ready_with_review_required_ownership_links"
        reason = "At least one production ownership link is present; human review is still required before S06 promotion."
    else:
        status = "not_accepted_review_required_converged_no_object_owner_root"
        s06_readiness = "blocked_until_s05_object_like_owner_root"
        reason = (
            "S05 recovered coherent TPIDR/per-CPU field, writer, and bridge evidence, "
            "but no object-like owner root tied to VM/vCPU/Stage-2 resource identity."
        )

    result = {
        "producer": "integrate-hypervisor-runtime-model/scripts/finalize_s05_convergence_gate.py",
        "stage_id": "S05",
        "iteration_id": "S05-RW18",
        "policy": "local_artifact_convergence_gate",
        "input_artifacts": [
            "runtime-object-model.json",
            "s05-rw8-root-classification.json",
            "s05-rw13-global-value-source-trace.json",
            "s05-rw14-tpidr-offset-family-trace.json",
            "s05-rw15-tpidr-writer-lifecycle-trace.json",
            "s05-rw16-lifecycle-bridge-trace.json",
            "s05-rw17-cross-function-arg-bridge.json",
        ],
        "production_counts": production_counts,
        "positive_review_evidence": positive_review_evidence,
        "negative_findings": negative_findings,
        "blocking_unknowns": blocking_unknowns,
        "review_only_link_count": len(review_links),
        "ownership_link_count": len(ownership_links),
        "summary": {
            "production_ready_total": production_ready_total,
            "ownership_link_count": len(ownership_links),
            "review_only_link_count": len(review_links),
            "blocking_unknown_count": len(blocking_unknowns),
            "s05_development_loop_converged": True,
            "s05_status": status,
            "s06_readiness": s06_readiness,
        },
        "decision": {
            "status": status,
            "s06_readiness": s06_readiness,
            "reason": reason,
            "recommended_next_step": "Stop blind S05 expansion. Either perform human review on RW14-RW17 review seeds, provide new evidence, or enter S06 only in explicitly review-seed mode.",
        },
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fp:
        json.dump(result, fp, ensure_ascii=False, indent=2)
        fp.write("\n")
    print(str(OUT))


if __name__ == "__main__":
    main()
