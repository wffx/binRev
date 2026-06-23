# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

from .models import AnalysisResult

INVARIANTS = (
    {
        "id": "MEM-001",
        "title": "Cross-VM Stage-2 isolation",
        "statement": "A VM must not map pages owned by another VM.",
        "required_evidence": [
            "VM ownership metadata type",
            "Stage-2 map/unmap call graph",
            "VMID and VTTBR_EL2 update sites",
        ],
    },
    {
        "id": "HKIP-001",
        "title": "Hypervisor write protection",
        "statement": "Normal VM mapping paths must not make HKIP-protected pages writable.",
        "required_evidence": [
            "Protected region boundaries",
            "Permission update paths",
            "TLB invalidation and barrier sequence",
        ],
    },
    {
        "id": "CTX-001",
        "title": "vCPU context ownership",
        "statement": "A vCPU context must remain bound to exactly one VM.",
        "required_evidence": [
            "vCPU and VM structure types",
            "World-switch save/restore path",
            "Scheduler enqueue and migration paths",
        ],
    },
    {
        "id": "IRQ-001",
        "title": "Interrupt route ownership",
        "statement": "A physical interrupt may only be injected into its bound VM/vCPU.",
        "required_evidence": [
            "Physical-to-virtual IRQ route table",
            "ICH list-register programming",
            "Route teardown path",
        ],
    },
    {
        "id": "LIFE-001",
        "title": "VM destruction cleanup",
        "statement": "VM destruction must release VMID, mappings, IRQ routes and CPU bindings.",
        "required_evidence": [
            "VM lifecycle state machine",
            "Destruction rollback paths",
            "Allocator and route-table call graph",
        ],
    },
)


def build_invariant_report(result: AnalysisResult) -> dict:
    register_names = {item.register for item in result.sysregs}
    event_kinds = {item.kind for item in result.events}
    reports = []
    for invariant in INVARIANTS:
        hints: list[str] = []
        if invariant["id"] == "MEM-001":
            for name in ("VTCR_EL2", "VTTBR_EL2", "HPFAR_EL2"):
                if name in register_names:
                    hints.append(f"recognized {name} access")
        elif invariant["id"] == "HKIP-001":
            if event_kinds & {"data-sync-barrier", "instruction-barrier"}:
                hints.append("recognized permission-ordering barrier candidate")
        elif invariant["id"] == "CTX-001":
            for name in ("ELR_EL2", "SPSR_EL2", "SP_EL1"):
                if name in register_names:
                    hints.append(f"recognized {name} context access")
        elif invariant["id"] == "IRQ-001":
            if any(name.startswith(("ICH_", "ICC_")) for name in register_names):
                hints.append("recognized GIC virtual interface access")
        elif invariant["id"] == "LIFE-001":
            if "hypervisor-call" in event_kinds:
                hints.append("recognized HVC dispatch candidate")
        reports.append(
            {
                **invariant,
                "status": "not-evaluated",
                "evidence_hints": hints,
                "decision": (
                    "Static instruction evidence is insufficient; recover the listed "
                    "types and call paths before evaluating this invariant."
                ),
            }
        )
    return {"schema_version": 1, "invariants": reports}
