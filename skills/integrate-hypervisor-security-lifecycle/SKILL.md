---
name: integrate-hypervisor-security-lifecycle
description: "Integrate S07 VM lifecycle and HKIP outputs into a unified security-lifecycle model. Use to cross-check VMID, page, IRQ, CPU binding, permission, rollback, teardown, protected-region, and violation-path relationships before S08 synthesis and S09 audit."
---

# Integrate Hypervisor Security Lifecycle

## Purpose

Merge lifecycle and HKIP candidates into a security-lifecycle model for repository synthesis and static security audit. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S07/vm-lifecycle-model.json`
- `S07/hkip-model.json`
- `S07/state-transitions.jsonl`
- `S06/service-model.json`
- `S05/resource-ownership.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Verify upstream readiness.
   - Require accepted S03-S06 and valid S07 worker outputs.
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

## Outputs

Produce:

- `S07/security-lifecycle-model.json`
- `S07/ida-change-proposal.json`
- `S07/records/integrate-hypervisor-security-lifecycle.evidence.jsonl`
- `S07/records/integrate-hypervisor-security-lifecycle.decisions.jsonl`
- `S07/records/integrate-hypervisor-security-lifecycle.unknowns.jsonl`

## Boundaries

- Do not perform S09 invariant verdicts.
- Do not hide missing teardown or protection evidence.
- Do not apply IDA writes directly.
