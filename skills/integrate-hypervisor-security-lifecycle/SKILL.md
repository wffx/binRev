---
name: integrate-hypervisor-security-lifecycle
description: "Integrate S07 VM lifecycle and HKIP outputs into a unified security-lifecycle model. Use to cross-check VMID, page, IRQ, CPU binding, permission, rollback, teardown, protected-region, and violation-path relationships before S08 synthesis and S09 audit."
---

# Integrate Hypervisor Security Lifecycle

## Purpose

Merge lifecycle and HKIP candidates into a security-lifecycle model for repository synthesis and static security audit. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

Support two modes:

- `production`: consume accepted S03-S06 plus valid S07 worker outputs and emit confirmed/candidate security-lifecycle relationships.
- `review_seed`: consume S05/S06 review-seed artifacts when production is blocked by missing object/resource identity, and emit only `review_seed` / `model_hypothesis` / `absent_or_unknown` outputs.

## Inputs

Production requires:

- `S07/vm-lifecycle-model.json`
- `S07/hkip-model.json`
- `S07/state-transitions.jsonl`
- `S06/service-model.json`
- `S05/resource-ownership.jsonl`
- accepted IDA checkpoint or IDA MCP session

Review-seed requires:

- `S05/runtime-object-model.json`
- `S05/s05-rw18-convergence-gate.json`
- `S06/stage-manifest.json`
- `S06/service-model.json`
- `S06/scheduler-model.json`
- `S06/interrupt-model.json`
- `S06/vm-config-model.json`
- `S06/state-machines.jsonl`

## Workflow

1. Verify upstream readiness.
   - Require accepted S03-S06 and valid S07 worker outputs.
   - If S06 status is `review_seed_ready_production_blocked`, switch to review-seed mode instead of failing the entire downstream workflow.
   - If lifecycle or HKIP is absent, record explicit `absent_or_unknown` rather than inventing it.

2. Cross-check transitions.
   - Verify VMID/page/IRQ/CPU binding changes across create/start/pause/resume/destroy/rollback candidates.
   - Link HKIP permission changes to lifecycle or service operations only with evidence.

3. Build security-lifecycle model.
   - Emit protected regions, state transitions, resource effects, violation paths, and blocking unknowns.
   - Prepare invariant inputs for S09 without performing final audit.

4. Generate IDA proposal.
   - Propose only reviewed candidate comments/names.
   - Keep high-risk security names review-only.

5. For review-seed mode, run:

```text
scripts/generate_s07_review_seed_security_lifecycle.py
```

   This script must not read Oracle/symbolized samples. It creates lifecycle/HKIP/security-lifecycle review seeds while leaving production links empty.

## Outputs

Produce:

- `S07/lifecycle-model.json`
- `S07/security-lifecycle-model.json`
- `S07/resource-transitions.jsonl`
- `S07/stage-manifest.json`
- `S07/artifact-validation-rw1.json`
- `S07/ida-change-proposal-rw1.json`
- `S07/records/integrate-hypervisor-security-lifecycle.evidence.jsonl`
- `S07/records/integrate-hypervisor-security-lifecycle.decisions.jsonl`
- `S07/records/integrate-hypervisor-security-lifecycle.unknowns.jsonl`

## Boundaries

- Do not perform S09 invariant verdicts.
- Do not hide missing teardown or protection evidence.
- Do not apply IDA writes directly.
- Do not use validation-only Oracle/symbolized samples as production evidence.
- Do not promote `model_hypothesis` lifecycle or HKIP records to confirmed source semantics.
