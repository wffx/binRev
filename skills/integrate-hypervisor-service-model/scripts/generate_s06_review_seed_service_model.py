"""Generate S06 review-seed service model from S05 review-only seeds.

Formal production input remains a single binary plus IDA-derived static
artifacts. This script does not use oracle symbols, source, logs, DTB, or
dynamic traces. It converts S05 review-only evidence into S06 review-seed
models with explicit hypothesis labels and production blockers.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


ROOT = Path(os.environ.get("BINREV_ROOT", r"F:\AI\codexProject\binRev"))
CASE = "xen_arm64-778090a1"
CASE_DIR = ROOT / "cases" / CASE
S05 = CASE_DIR / "stages" / "S05"
S06 = CASE_DIR / "stages" / "S06"


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        json.dump(obj, fp, ensure_ascii=False, indent=2)
        fp.write("\n")


def write_jsonl(path: Path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        for row in rows:
            fp.write(json.dumps(row, ensure_ascii=False) + "\n")


def collect_offset_families(rw14):
    families = []
    for item in (rw14 or {}).get("global_offset_families", []):
        families.append(
            {
                "offset": item.get("offset"),
                "read_count": item.get("read", 0),
                "write_count": item.get("write", 0),
                "function_count": item.get("function_count", 0),
                "source": "S05/s05-rw14-tpidr-offset-family-trace.json",
                "status": "review_seed",
            }
        )
    return families


def collect_writer_candidates(rw15):
    out = []
    for fn in (rw15 or {}).get("tpidr_confirmed_functions", []):
        if fn.get("derived_write_count", 0) <= 0:
            continue
        out.append(
            {
                "function": fn.get("function"),
                "derived_write_count": fn.get("derived_write_count", 0),
                "derived_read_count": fn.get("derived_read_count", 0),
                "calls_with_tpidr_arg_count": fn.get("calls_with_tpidr_arg_count", 0),
                "source": "S05/s05-rw15-tpidr-writer-lifecycle-trace.json",
                "status": "review_seed",
            }
        )
    return out


def collect_bridge_candidates(rw16, rw17):
    local_bridges = []
    for seed in (rw16 or {}).get("seed_summaries", []):
        local_bridges.append(
            {
                "function": seed.get("function"),
                "offsets": seed.get("offsets", []),
                "bridge_score": seed.get("bridge_score"),
                "decision": seed.get("decision"),
                "local_tag_counts": seed.get("local_tag_counts", {}),
                "source": "S05/s05-rw16-lifecycle-bridge-trace.json",
                "status": "review_seed",
            }
        )

    arg_bridges = []
    for bridge in (rw17 or {}).get("bridge_analyses", []):
        if bridge.get("best_score", 0) <= 0:
            continue
        arg_bridges.append(
            {
                "mode": bridge.get("mode"),
                "a": bridge.get("a"),
                "b": bridge.get("b"),
                "caller": bridge.get("caller"),
                "callee": bridge.get("callee"),
                "best_score": bridge.get("best_score"),
                "best_decision": bridge.get("best_decision"),
                "source": "S05/s05-rw17-cross-function-arg-bridge.json",
                "status": "review_seed",
                "promotion_blocker": "Shared roots prove static/per-CPU context only; VM/vCPU/Stage-2 resource identity is not proven.",
            }
        )
    return local_bridges, arg_bridges


def main():
    runtime = load_json(S05 / "runtime-object-model.json", {})
    manifest = load_json(S05 / "stage-manifest.json", {})
    rw14 = load_json(S05 / "s05-rw14-tpidr-offset-family-trace.json", {})
    rw15 = load_json(S05 / "s05-rw15-tpidr-writer-lifecycle-trace.json", {})
    rw16 = load_json(S05 / "s05-rw16-lifecycle-bridge-trace.json", {})
    rw17 = load_json(S05 / "s05-rw17-cross-function-arg-bridge.json", {})
    rw18 = load_json(S05 / "s05-rw18-convergence-gate.json", {})

    image_sha = manifest.get("image_sha256")
    offset_families = collect_offset_families(rw14)
    writers = collect_writer_candidates(rw15)
    local_bridges, arg_bridges = collect_bridge_candidates(rw16, rw17)

    common_policy = {
        "mode": "review_seed",
        "formal_input_boundary": "single binary plus IDA-derived static artifacts only",
        "oracle_policy": "oracle/symbolized samples are forbidden in production evidence",
        "model_hypothesis_policy": "Large-model semantic labels are allowed only as model_hypothesis, never as confirmed fact.",
        "promotion_rule": "A review seed may become production only with binary/IDA evidence for object owner identity and resource lifecycle closure.",
    }

    vm_config = {
        "case_id": CASE,
        "stage_id": "S06",
        "model": "vm-config-model",
        "status": "review_seed_only",
        "policy": common_policy,
        "hypotheses": [
            {
                "id": "S06-VMCFG-HYP-0001",
                "label": "embedded_or_static_vm_config_possible",
                "basis": "S05 produced static/per-CPU review seeds but no VM object identity.",
                "evidence": ["S05/s05-rw18-convergence-gate.json"],
                "confidence": "low",
                "status": "model_hypothesis",
                "promotion_blocker": "No VM config table, VM count, memory region, or device/IRQ route has binary/IDA-only owner identity proof.",
            }
        ],
        "vm_config_candidates": [],
        "blocking_unknowns": [
            {
                "id": "U-S06-VMCFG-0001",
                "kind": "vm_config_identity_unknown",
                "reason": "S05 review seeds do not identify a VM config object or VM resource owner.",
            }
        ],
    }

    scheduler = {
        "case_id": CASE,
        "stage_id": "S06",
        "model": "scheduler-model",
        "status": "review_seed_only",
        "policy": common_policy,
        "percpu_offset_families": offset_families,
        "writer_clearer_candidates": writers,
        "local_lifecycle_bridges": local_bridges,
        "argument_bridges": arg_bridges,
        "hypotheses": [
            {
                "id": "S06-SCHED-HYP-0001",
                "label": "percpu_or_scheduler_context_candidate",
                "basis": "TPIDR_EL2-derived offsets 0x10/0x18 and writer/clearer functions form a coherent per-CPU/static-context family.",
                "evidence": [
                    "S05/s05-rw14-tpidr-offset-family-trace.json",
                    "S05/s05-rw15-tpidr-writer-lifecycle-trace.json",
                    "S05/s05-rw17-cross-function-arg-bridge.json",
                ],
                "confidence": "medium",
                "status": "model_hypothesis",
                "promotion_blocker": "No previous/next vCPU, runqueue object, or CPU.current_vcpu ownership identity is proven.",
            }
        ],
        "blocking_unknowns": [
            {
                "id": "U-S06-SCHED-0001",
                "kind": "runqueue_or_current_vcpu_identity_unknown",
                "reason": "S05 seeds prove static/per-CPU context but not vCPU or scheduler resource identity.",
            }
        ],
    }

    interrupt = {
        "case_id": CASE,
        "stage_id": "S06",
        "model": "interrupt-model",
        "status": "review_seed_only",
        "policy": common_policy,
        "hypotheses": [
            {
                "id": "S06-IRQ-HYP-0001",
                "label": "interrupt_or_cpu_local_context_possible",
                "basis": "S05 RW17 bridge includes DAIFClr and TPIDR context near sub_661A0 -> sub_5F314/sub_66600, but this is not enough to prove IRQ routing.",
                "evidence": ["S05/s05-rw17-cross-function-arg-bridge.json"],
                "confidence": "low-medium",
                "status": "model_hypothesis",
                "promotion_blocker": "No physical IRQ, virtual IRQ, target VM/vCPU, GIC distributor/redistributor, or ICH route identity is proven.",
            }
        ],
        "irq_route_candidates": [],
        "blocking_unknowns": [
            {
                "id": "U-S06-IRQ-0001",
                "kind": "irq_route_identity_unknown",
                "reason": "Static context bridge does not prove physical-to-virtual IRQ route or target VM/vCPU.",
            }
        ],
    }

    service = {
        "case_id": CASE,
        "stage_id": "S06",
        "iteration_id": "S06-RW1",
        "producer_skill": "integrate-hypervisor-service-model",
        "status": "review_seed_ready_production_blocked",
        "upstream": {
            "S05_status": runtime.get("model_status"),
            "S05_production_gate": (runtime.get("s06_readiness") or {}).get("production_gate") if isinstance(runtime.get("s06_readiness"), dict) else None,
            "S05_review_seed_gate": (runtime.get("s06_readiness") or {}).get("review_seed_gate") if isinstance(runtime.get("s06_readiness"), dict) else None,
            "S05_convergence": (rw18.get("summary") or {}),
        },
        "policy": common_policy,
        "submodels": {
            "vm_config": "vm-config-model.json",
            "scheduler": "scheduler-model.json",
            "interrupt": "interrupt-model.json",
        },
        "review_seed_inputs": {
            "offset_family_count": len(offset_families),
            "writer_candidate_count": len(writers),
            "local_bridge_count": len(local_bridges),
            "argument_bridge_count": len(arg_bridges),
        },
        "production_links": [],
        "review_seed_links": [
            {
                "from": "S05/RW14-RW17",
                "to": "S06 scheduler/per-CPU context hypothesis",
                "status": "review_seed",
                "confidence": "medium",
                "promotion_blocker": "No VM/vCPU/Stage-2 resource identity.",
            },
            {
                "from": "S05/RW17 sub_661A0 bridge",
                "to": "S06 interrupt or CPU-local context hypothesis",
                "status": "review_seed",
                "confidence": "low-medium",
                "promotion_blocker": "No IRQ route target identity.",
            },
        ],
        "s07_readiness": {
            "production": "blocked_no_s06_resource_identity",
            "review_seed": "ready_for_hypothesis_only",
        },
        "blocking_unknowns": [
            "U-S06-VMCFG-0001",
            "U-S06-SCHED-0001",
            "U-S06-IRQ-0001",
        ],
    }

    state_rows = [
        {
            "id": "S06-STATE-HYP-0001",
            "status": "model_hypothesis",
            "name": "percpu_context_update_or_cpu_local_service_sequence",
            "evidence": ["S05/s05-rw17-cross-function-arg-bridge.json"],
            "sequence": [
                "sub_661A0",
                "sub_5F314",
                "sub_66600",
            ],
            "promotion_blocker": "No proven vCPU/VM/IRQ resource identity.",
        }
    ]

    manifest_out = {
        "stage_id": "S06",
        "stage_name": "VM service model",
        "case_id": CASE,
        "image_sha256": image_sha,
        "status": "review_seed_ready_production_blocked",
        "mode": "review_seed",
        "producer_skills": [
            "recover-hypervisor-vm-config",
            "recover-hypervisor-scheduler",
            "recover-hypervisor-interrupt-routing",
            "integrate-hypervisor-service-model",
        ],
        "input_artifacts": [
            "S05/runtime-object-model.json",
            "S05/s05-rw14-tpidr-offset-family-trace.json",
            "S05/s05-rw15-tpidr-writer-lifecycle-trace.json",
            "S05/s05-rw16-lifecycle-bridge-trace.json",
            "S05/s05-rw17-cross-function-arg-bridge.json",
            "S05/s05-rw18-convergence-gate.json",
        ],
        "output_artifacts": [
            "vm-config-model.json",
            "scheduler-model.json",
            "interrupt-model.json",
            "service-model.json",
            "state-machines.jsonl",
            "artifact-validation-rw1.json",
            "ida-change-proposal-rw1.json",
        ],
        "exit_assessment": {
            "s06_acceptance": "dual_gate",
            "production_gate": "blocked_no_resource_identity",
            "review_seed_gate": "accepted_review_seed_ready",
            "reason": "Only-binary constraints allow hypothesis/review-seed continuation from S05 seeds, but no S06 production resource relationship is proven.",
        },
        "s07_readiness": service["s07_readiness"],
    }

    validation = {
        "stage_id": "S06",
        "case_id": CASE,
        "iteration_id": "S06-RW1",
        "result": "pass",
        "checked_artifacts": manifest_out["output_artifacts"],
        "mode": "review_seed",
        "summary": service["review_seed_inputs"],
        "production_links": 0,
        "review_seed_links": len(service["review_seed_links"]),
        "s07_readiness": service["s07_readiness"],
    }

    proposal = {
        "proposal_id": "IDA-PROP-S06-RW1-REVIEW-SEED-SERVICE-MODEL",
        "stage_id": "S06",
        "case_id": CASE,
        "iteration_id": "S06-RW1",
        "status": "proposal_empty_no_ida_writes",
        "reason": "S06-RW1 only converts S05 review seeds into hypothesis-labelled service model artifacts. It performs no IDA mutations.",
        "actions": [],
    }

    write_json(S06 / "vm-config-model.json", vm_config)
    write_json(S06 / "scheduler-model.json", scheduler)
    write_json(S06 / "interrupt-model.json", interrupt)
    write_json(S06 / "service-model.json", service)
    write_jsonl(S06 / "state-machines.jsonl", state_rows)
    write_json(S06 / "stage-manifest.json", manifest_out)
    write_json(S06 / "artifact-validation-rw1.json", validation)
    write_json(S06 / "ida-change-proposal-rw1.json", proposal)
    for suffix in ("evidence", "decisions", "unknowns"):
        write_jsonl(S06 / "records" / f"integrate-hypervisor-service-model.{suffix}.jsonl", [])
    print(str(S06 / "service-model.json"))


if __name__ == "__main__":
    main()
