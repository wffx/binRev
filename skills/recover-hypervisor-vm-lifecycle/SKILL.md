---
name: recover-hypervisor-vm-lifecycle
description: "Recover S07 VM lifecycle candidates from accepted S06 service and S05 ownership evidence. Use when the workflow needs create, load, start, pause, resume, reset, destroy, error rollback, VMID/page/IRQ/CPU-binding resource transitions, and lifecycle state machines."
---

# Recover Hypervisor VM Lifecycle

## Purpose

Recover VM lifecycle and resource transition candidates. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

If upstream S06 is `review_seed_ready_production_blocked`, operate in review-seed mode: carry forward only explicitly labelled `model_hypothesis` lifecycle seeds and keep VM create/load/start/pause/resume/reset/destroy semantics unknown unless binary/IDA evidence proves VM/vCPU/resource identity.

## Inputs

Require:

- `S06/service-model.json`
- `S06/state-machines.jsonl`
- `S05/resource-ownership.jsonl`
- `S05/runtime-object-model.json`
- `S03/call-graph.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S06.
   - If S06 is review-seed-only, do not fail the workflow; emit `review_seed_only` outputs and block production lifecycle.
   - If service references are not stable, emit `blocked_by_upstream`.

2. Identify lifecycle anchors.
   - Track allocation, initialization, load, start, stop, reset, destroy, rollback, and cleanup paths.
   - Keep unknown states as `state_0xN`.

3. Track resource transitions.
   - Record VMID, page ownership, IRQ route, CPU/vCPU binding, and context changes per transition.
   - Mark missing cleanup evidence as Unknown.
   - In review-seed mode, do not record VMID/page/IRQ/CPU-binding transitions as facts; record them only as missing resource identity blockers.

## Outputs

Produce:

- `S07/vm-lifecycle-model.json`
- `S07/state-transitions.jsonl`
- `S07/records/recover-hypervisor-vm-lifecycle.evidence.jsonl`
- `S07/records/recover-hypervisor-vm-lifecycle.decisions.jsonl`
- `S07/records/recover-hypervisor-vm-lifecycle.unknowns.jsonl`

## Boundaries

- Do not claim security invariants; integration and S09 audit own invariant checks.
- Do not infer lifecycle names from common hypervisor terminology alone.
- Do not convert per-CPU/static context sequences into VM lifecycle transitions without owner/resource closure.
- Do not apply IDA writes directly.
