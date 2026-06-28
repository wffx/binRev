#!/usr/bin/env python3
"""Generate S06 review-seed security lifecycle artifacts.

This pass is intentionally conservative. It consumes S05 review-seed
artifacts and emits only model hypotheses when S06 production evidence is
blocked by missing VM/vCPU/Stage-2 resource identity.

Oracle/symbolized samples are not inputs to this script.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_ID = "xen_arm64-778090a1"
ROOT = Path(__file__).resolve().parents[3]
CASE = ROOT / "cases" / CASE_ID
S05 = CASE / "stages" / "S05"
S06 = CASE / "stages" / "S06"
RECORDS = S06 / "records"


POLICY = {
    "mode": "review_seed",
    "formal_input_boundary": "single binary plus IDA-derived static artifacts only",
    "oracle_policy": "oracle/symbolized samples are forbidden in production evidence",
    "model_hypothesis_policy": "Large-model semantic labels are allowed only as model_hypothesis, never as confirmed fact.",
    "promotion_rule": (
        "A review seed may become production only with binary/IDA evidence for VM/vCPU/Stage-2 "
        "resource identity, lifecycle closure, and HKIP protected-object semantics."
    ),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            f.write("\n")


def load_inputs() -> dict[str, Any]:
    return {
        "s05_runtime": read_json(S05 / "runtime-object-model.json"),
        "s05_gate": read_json(S05 / "s05-rw18-convergence-gate.json"),
        "s05_manifest": read_json(S05 / "stage-manifest.json"),
        "s05_service": read_json(S05 / "service-model.json"),
        "s05_scheduler": read_json(S05 / "scheduler-model.json"),
        "s05_interrupt": read_json(S05 / "interrupt-model.json"),
        "s05_vm_config": read_json(S05 / "vm-config-model.json"),
        "s05_states": read_jsonl(S05 / "state-machines.jsonl"),
    }


def build_lifecycle_model(inputs: dict[str, Any]) -> dict[str, Any]:
    state_hypotheses = inputs["s05_states"]
    review_sequence = []
    for row in state_hypotheses:
        if row.get("status") == "model_hypothesis":
            review_sequence.append(
                {
                    "id": "S06-LC-HYP-0001",
                    "source_state_machine": row.get("id"),
                    "label": "cpu_local_or_percpu_context_transition_sequence",
                    "status": "model_hypothesis",
                    "confidence": "low-medium",
                    "sequence": row.get("sequence", []),
                    "evidence": row.get("evidence", []),
                    "allowed_interpretation": (
                        "A static/per-CPU context update sequence suitable for review; not a VM create/start/"
                        "pause/resume/destroy lifecycle."
                    ),
                    "promotion_blocker": "No proven VM/vCPU object, VMID, page ownership, IRQ route, or teardown closure.",
                }
            )

    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "model": "lifecycle-model",
        "iteration_id": "S06-RW1",
        "status": "review_seed_only",
        "generated_at": now_iso(),
        "policy": POLICY,
        "production_lifecycle_transitions": [],
        "review_seed_lifecycle_hypotheses": review_sequence,
        "vm_lifecycle_states": [],
        "resource_lifecycle_transitions": [],
        "blocking_unknowns": [
            {
                "id": "U-S06-LC-0001",
                "kind": "vm_lifecycle_identity_unknown",
                "reason": "S06 lacks confirmed VM/vCPU resource identity and therefore cannot support create/start/pause/resume/destroy semantics.",
            }
        ],
    }


def build_resource_transitions(inputs: dict[str, Any]) -> list[dict[str, Any]]:
    transitions: list[dict[str, Any]] = []
    service_links = inputs["s05_service"].get("review_seed_links", [])
    for idx, link in enumerate(service_links, 1):
        transitions.append(
            {
                "id": f"S06-RES-HYP-{idx:04d}",
                "status": "model_hypothesis",
                "kind": "review_seed_context_effect",
                "source": link.get("from"),
                "target": link.get("to"),
                "confidence": link.get("confidence", "unknown"),
                "resource_identity": "unknown",
                "resource_classes_not_proven": ["VM", "vCPU", "VMID", "Stage-2 page table", "IRQ route", "CPU binding"],
                "promotion_blocker": link.get("promotion_blocker", "No resource identity closure."),
            }
        )
    return transitions


def build_hkip_model(inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "model": "hkip-model",
        "iteration_id": "S06-RW1",
        "status": "absent_or_unknown_review_seed_only",
        "generated_at": now_iso(),
        "policy": POLICY,
        "protected_regions": [],
        "permission_toggle_paths": [],
        "write_windows": [],
        "integrity_metadata": [],
        "verification_paths": [],
        "violation_paths": [],
        "negative_findings": [
            {
                "id": "S06-HKIP-NEG-0001",
                "status": "review_seed",
                "finding": "No HKIP protected object, permission transition, integrity metadata, or violation handler is proven by S05/S06 artifacts.",
                "evidence": [
                    "S05/runtime-object-model.json",
                    "S06/service-model.json",
                    "S06/interrupt-model.json",
                ],
            }
        ],
        "blocking_unknowns": [
            {
                "id": "U-S06-HKIP-0001",
                "kind": "hkip_protected_object_unknown",
                "reason": "No protected hypervisor text/rodata/page-table/metadata object or HKIP-specific permission toggle has binary/IDA-only proof.",
            }
        ],
    }


def build_security_lifecycle(
    inputs: dict[str, Any],
    lifecycle_model: dict[str, Any],
    hkip_model: dict[str, Any],
    resource_transitions: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "model": "security-lifecycle-model",
        "iteration_id": "S06-RW1",
        "producer_skill": "integrate-hypervisor-security-lifecycle",
        "status": "review_seed_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "upstream": {
            "S05_status": inputs["s05_runtime"].get("model_status"),
            "S06_status": inputs["s05_manifest"].get("status"),
            "S06_production_readiness": inputs["s05_service"].get("s06_readiness", {}).get("production"),
            "S06_review_seed_readiness": inputs["s05_service"].get("s06_readiness", {}).get("review_seed"),
        },
        "production_security_lifecycle": {
            "status": "blocked",
            "reason": "No confirmed VM/vCPU/Stage-2 resource identity, lifecycle transition, or HKIP protected-object evidence.",
            "links": [],
        },
        "review_seed_security_lifecycle": {
            "status": "ready_for_review_only",
            "lifecycle_hypothesis_count": len(lifecycle_model["review_seed_lifecycle_hypotheses"]),
            "resource_transition_hypothesis_count": len(resource_transitions),
            "hkip_status": hkip_model["status"],
            "allowed_downstream_use": (
                "S08 may create unresolved/review-seed repository scaffolding and evidence indexes only; "
                "it must not synthesize confirmed lifecycle or HKIP code from these hypotheses."
            ),
        },
        "security_invariant_inputs": [],
        "blocking_unknowns": [
            "U-S06-LC-0001",
            "U-S06-HKIP-0001",
            "U-S06-RES-0001",
        ],
        "s07_readiness": {
            "production": "blocked_no_confirmed_lifecycle_or_hkip",
            "review_seed": "ready_for_unresolved_repository_seed",
        },
    }


def build_manifest(security_model: dict[str, Any]) -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "iteration_id": "S06-RW1",
        "producer_skill": "integrate-hypervisor-security-lifecycle",
        "status": "review_seed_ready_production_blocked",
        "generated_at": now_iso(),
        "inputs": [
            "S05/runtime-object-model.json",
            "S05/s05-rw18-convergence-gate.json",
            "S06/stage-manifest.json",
            "S06/service-model.json",
            "S06/scheduler-model.json",
            "S06/interrupt-model.json",
            "S06/vm-config-model.json",
            "S06/state-machines.jsonl",
        ],
        "outputs": [
            "S06/lifecycle-model.json",
            "S06/vm-lifecycle-model.json",
            "S06/hkip-model.json",
            "S06/resource-transitions.jsonl",
            "S06/state-transitions.jsonl",
            "S06/security-lifecycle-model.json",
            "S06/ida-change-proposal-rw1.json",
            "S06/artifact-validation-rw1.json",
        ],
        "policy": POLICY,
        "gates": {
            "production": {
                "status": "blocked",
                "reason": security_model["production_security_lifecycle"]["reason"],
            },
            "review_seed": {
                "status": "ready",
                "reason": "S06 review-seed hypotheses can be carried forward as explicitly labelled model_hypothesis records.",
            },
        },
        "s07_readiness": security_model["s07_readiness"],
        "blocking_unknowns": security_model["blocking_unknowns"],
    }


def build_validation(
    lifecycle_model: dict[str, Any],
    hkip_model: dict[str, Any],
    security_model: dict[str, Any],
    resource_transitions: list[dict[str, Any]],
) -> dict[str, Any]:
    checks = [
        {
            "id": "S06-VAL-0001",
            "check": "all production outputs remain empty while upstream production is blocked",
            "result": "pass"
            if not lifecycle_model["production_lifecycle_transitions"]
            and not security_model["production_security_lifecycle"]["links"]
            else "fail",
        },
        {
            "id": "S06-VAL-0002",
            "check": "HKIP is not confirmed without protected object and permission-transition evidence",
            "result": "pass" if hkip_model["status"] == "absent_or_unknown_review_seed_only" else "fail",
        },
        {
            "id": "S06-VAL-0003",
            "check": "resource transitions are review-seed hypotheses only",
            "result": "pass" if all(row.get("status") == "model_hypothesis" for row in resource_transitions) else "fail",
        },
    ]
    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "iteration_id": "S06-RW1",
        "result": "pass" if all(row["result"] == "pass" for row in checks) else "fail",
        "checks": checks,
    }


def build_ida_proposal() -> dict[str, Any]:
    return {
        "case_id": CASE_ID,
        "stage_id": "S06",
        "iteration_id": "S06-RW1",
        "status": "empty_no_safe_ida_mutation",
        "policy": POLICY,
        "actions": [],
        "reason": (
            "S06-RW1 has only lifecycle/security hypotheses and unknowns. It does not propose function names, "
            "types, comments, or source mappings for IDA."
        ),
    }


def main() -> None:
    inputs = load_inputs()
    lifecycle_model = build_lifecycle_model(inputs)
    resource_transitions = build_resource_transitions(inputs)
    hkip_model = build_hkip_model(inputs)
    security_model = build_security_lifecycle(inputs, lifecycle_model, hkip_model, resource_transitions)
    manifest = build_manifest(security_model)
    validation = build_validation(lifecycle_model, hkip_model, security_model, resource_transitions)
    ida_proposal = build_ida_proposal()

    write_json(S06 / "lifecycle-model.json", lifecycle_model)
    write_json(S06 / "vm-lifecycle-model.json", lifecycle_model)
    write_json(S06 / "hkip-model.json", hkip_model)
    write_jsonl(S06 / "resource-transitions.jsonl", resource_transitions)
    write_jsonl(
        S06 / "state-transitions.jsonl",
        lifecycle_model["review_seed_lifecycle_hypotheses"],
    )
    write_json(S06 / "security-lifecycle-model.json", security_model)
    write_json(S06 / "stage-manifest.json", manifest)
    write_json(S06 / "artifact-validation-rw1.json", validation)
    write_json(S06 / "ida-change-proposal-rw1.json", ida_proposal)

    evidence_rows = [
        {
            "id": "E-S06-RW1-0001",
            "kind": "upstream_gate",
            "status": "review_seed",
            "evidence": "S06/stage-manifest.json",
            "summary": "S06 production is blocked but review-seed readiness permits hypothesis-only S06 continuation.",
        },
        {
            "id": "E-S06-RW1-0002",
            "kind": "lifecycle_seed",
            "status": "model_hypothesis",
            "evidence": "S06/state-machines.jsonl",
            "summary": "S06 exposes a per-CPU/static context sequence, not a confirmed VM lifecycle.",
        },
        {
            "id": "E-S06-RW1-0003",
            "kind": "negative_hkip_evidence",
            "status": "review_seed",
            "evidence": "S06/service-model.json",
            "summary": "No HKIP protected object or permission-transition evidence is available from S05/S06.",
        },
    ]
    decision_rows = [
        {
            "id": "D-S06-RW1-0001",
            "decision": "run_s06_in_review_seed_mode",
            "rationale": "S06 has hypothesis-only service seeds and no production resource identity.",
        },
        {
            "id": "D-S06-RW1-0002",
            "decision": "do_not_confirm_hkip",
            "rationale": "No protected region, write window, integrity metadata, or violation path is proven.",
        },
    ]
    unknown_rows = [
        {
            "id": "U-S06-LC-0001",
            "kind": "vm_lifecycle_identity_unknown",
            "reason": "No confirmed VM/vCPU lifecycle owner or transition closure.",
        },
        {
            "id": "U-S06-HKIP-0001",
            "kind": "hkip_protected_object_unknown",
            "reason": "No protected object or HKIP permission transition.",
        },
        {
            "id": "U-S06-RES-0001",
            "kind": "resource_transition_owner_unknown",
            "reason": "No VMID/page/IRQ/CPU-binding owner identity.",
        },
    ]
    write_jsonl(RECORDS / "integrate-hypervisor-security-lifecycle.evidence.jsonl", evidence_rows)
    write_jsonl(RECORDS / "integrate-hypervisor-security-lifecycle.decisions.jsonl", decision_rows)
    write_jsonl(RECORDS / "integrate-hypervisor-security-lifecycle.unknowns.jsonl", unknown_rows)
    write_jsonl(RECORDS / "recover-hypervisor-vm-lifecycle.evidence.jsonl", evidence_rows[:2])
    write_jsonl(RECORDS / "recover-hypervisor-vm-lifecycle.decisions.jsonl", decision_rows[:1])
    write_jsonl(RECORDS / "recover-hypervisor-vm-lifecycle.unknowns.jsonl", unknown_rows[:1])
    write_jsonl(RECORDS / "recover-hypervisor-hkip-model.evidence.jsonl", evidence_rows[2:])
    write_jsonl(RECORDS / "recover-hypervisor-hkip-model.decisions.jsonl", decision_rows[1:])
    write_jsonl(RECORDS / "recover-hypervisor-hkip-model.unknowns.jsonl", unknown_rows[1:2])

    print(
        json.dumps(
            {
                "stage": "S06",
                "iteration": "S06-RW1",
                "status": manifest["status"],
                "validation": validation["result"],
                "resource_transition_hypotheses": len(resource_transitions),
                "s07_readiness": manifest["s07_readiness"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
