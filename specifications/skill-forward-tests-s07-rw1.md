# S07-RW1 Review-Seed Security Lifecycle Forward Test

S07-RW1 was generated after S06-RW1 in review-seed mode. The formal production boundary remains unchanged: only the target binary and IDA-derived static artifacts are allowed as evidence. Oracle/symbolized samples are validation-only and are not inputs to S07.

## New implementation

- `skills/integrate-hypervisor-security-lifecycle/scripts/generate_s07_review_seed_security_lifecycle.py`

## New artifacts

- `cases/xen_arm64-778090a1/stages/S07/lifecycle-model.json`
- `cases/xen_arm64-778090a1/stages/S07/vm-lifecycle-model.json`
- `cases/xen_arm64-778090a1/stages/S07/hkip-model.json`
- `cases/xen_arm64-778090a1/stages/S07/resource-transitions.jsonl`
- `cases/xen_arm64-778090a1/stages/S07/state-transitions.jsonl`
- `cases/xen_arm64-778090a1/stages/S07/security-lifecycle-model.json`
- `cases/xen_arm64-778090a1/stages/S07/stage-manifest.json`
- `cases/xen_arm64-778090a1/stages/S07/artifact-validation-rw1.json`
- `cases/xen_arm64-778090a1/stages/S07/ida-change-proposal-rw1.json`
- `cases/xen_arm64-778090a1/stages/S07/records/*.jsonl`

## Result

| Item | Value |
|---|---:|
| lifecycle hypotheses | 1 |
| resource transition hypotheses | 2 |
| production security-lifecycle links | 0 |
| HKIP status | `absent_or_unknown_review_seed_only` |
| validation | `pass` |

## Gate status

- S07 status: `review_seed_ready_production_blocked`
- Production gate: blocked because there is no confirmed VM/vCPU/Stage-2 resource identity, lifecycle transition, or HKIP protected-object evidence.
- Review-seed gate: ready for S08 unresolved/review-seed repository scaffolding only.

## Skill optimizations from this run

- `integrate-hypervisor-security-lifecycle` now has an explicit review-seed mode.
- `recover-hypervisor-vm-lifecycle` must not promote static/per-CPU context sequences into VM lifecycle transitions without owner/resource closure.
- `recover-hypervisor-hkip-model` must emit `absent_or_unknown` when no protected object, permission toggle, integrity metadata, write window, or violation path is proven.
