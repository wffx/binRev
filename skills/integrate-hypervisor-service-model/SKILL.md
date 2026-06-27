---
name: integrate-hypervisor-service-model
description: "Integrate S06 VM config, scheduler, and interrupt-routing outputs into a unified hypervisor service model. Use to reconcile VM/vCPU/device/IRQ references, state machines, service relationships, blocking conflicts, and reviewed IDA proposals without applying them."
---

# Integrate Hypervisor Service Model

## Purpose

Merge S06 service workers into a S07-consumable service model. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

Support two gates:

- `production`: requires S05 production ownership/resource identity.
- `review_seed`: allowed when S05 production is blocked but S05 has internally evidenced review seeds. Every downstream relationship must be labelled `review_seed` or `model_hypothesis`; never promote to confirmed ownership.

## Inputs

Require:

- `S06/vm-config-model.json`
- `S06/scheduler-model.json`
- `S06/interrupt-model.json`
- `S06/state-machines.jsonl`
- `S05/runtime-object-model.json`
- `S05/resource-ownership.jsonl`
- accepted IDA checkpoint or IDA MCP session

For legacy v1 review-seed mode only, also accept:

- `S05/s05-rw14-tpidr-offset-family-trace.json`
- `S05/s05-rw15-tpidr-writer-lifecycle-trace.json`
- `S05/s05-rw16-lifecycle-bridge-trace.json`
- `S05/s05-rw17-cross-function-arg-bridge.json`
- `S05/s05-rw18-convergence-gate.json`

## Workflow

1. Verify upstream readiness.
   - Require accepted S03-S05 and valid S06 worker outputs.
   - If any worker is blocked, emit service model with `s07_readiness: blocked`.
   - If S05 has `production_gate: blocked` but `review_seed_gate: ready`, run review-seed mode instead of failing the stage.
   - In review-seed mode, use `scripts/generate_s06_review_seed_service_model.py` to create S06 hypothesis-labelled artifacts from S05 RW14-RW18. Do not require VM/vCPU/Stage-2 production ownership links.

2. Reconcile references.
   - Link VM, vCPU, CPU, device, IRQ, and memory-region references.
   - Detect conflicting ownership, route targets, or state transitions.
   - In review-seed mode, preserve links as `review_seed_links`; set `production_links: []` unless binary/IDA evidence proves resource identity.

3. Build service model.
   - Preserve config, scheduler, and interrupt submodels as references.
   - Emit unified state-machine candidates and blocking unknowns.
   - In review-seed mode, emit hypotheses for VM config, scheduler, and interrupt only when they are explicitly backed by S05 review seeds. Include promotion blockers for every hypothesis.

4. Generate IDA proposal.
   - Propose only reviewed candidate comments/names.
   - Do not propose lifecycle or HKIP names in S06.

## Outputs

Produce:

- `S06/service-model.json`
- `S06/ida-change-proposal.json`
- `S06/records/integrate-hypervisor-service-model.evidence.jsonl`
- `S06/records/integrate-hypervisor-service-model.decisions.jsonl`
- `S06/records/integrate-hypervisor-service-model.unknowns.jsonl`

## Boundaries

- Do not recover lifecycle, teardown completeness, or HKIP.
- Do not repair S05 ownership silently.
- Do not apply IDA writes directly.
- Do not use oracle, symbolized samples, source code, logs, DTB, or dynamic traces in production mode.
- Do not let large-model semantic guesses become confirmed service relationships. Label them `model_hypothesis`.

## Workflow v2 override: S06 type and object propagation

When the workflow uses `workflow-source-recovery-v2.md`, this Skill acts as S06 type, structure, global object, and argument propagation.

This v2 contract supersedes the legacy S06/S07 service-model contract above. In v2, do not require or consume legacy review-seed files such as `S05/s05-rw15-*` or `S05/s05-rw17-*` unless a lab note explicitly asks for backward-compatibility analysis.

Use v2 inputs:

- `S03/functions.jsonl` or an equivalent IDA function export
- `S04/architecture-model.json` or sysreg/MMIO event export
- `S05/function-clusters.json`
- `S05/module-attribution.json`
- IDA decompile/disassembly evidence for clustered functions

Produce these primary artifacts:

- `S06/type-candidates.json`
- `S06/struct-layouts.jsonl`
- `S06/global-object-model.json`
- `S06/argument-flow.jsonl`
- `S06/ida-type-proposal.json`

Infer offset families, global roots, scalar/config/count globals, and cross-function argument roots. Separate confirmed layouts from hypotheses. Do not generate source code and do not use Oracle names as production evidence.

In corpus-wide mode, emit `S06/name-candidates.jsonl` for every clustered function. Prefer evidence-backed semantic names, otherwise use stable module-local names and keep addresses only in comments/source maps.
