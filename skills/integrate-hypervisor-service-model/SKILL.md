---
name: integrate-hypervisor-service-model
description: "Integrate S05 VM config, scheduler, and interrupt-routing outputs into a unified hypervisor service model. Use to reconcile VM/vCPU/device/IRQ references, state machines, service relationships, blocking conflicts, and reviewed IDA proposals without applying them."
---

# Integrate Hypervisor Service Model

## Purpose

Merge S05 service workers into a S06-consumable service model. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

Support two gates:

- `production`: requires S05 production ownership/resource identity.
- `review_seed`: allowed when S05 production is blocked but S05 has internally evidenced review seeds. Every downstream relationship must be labelled `review_seed` or `model_hypothesis`; never promote to confirmed ownership.

## Inputs

Require:

- `S05/vm-config-model.json`
- `S05/scheduler-model.json`
- `S05/interrupt-model.json`
- `S05/state-machines.jsonl`
- `S04/runtime-object-model.json`
- `S04/resource-ownership.jsonl`
- accepted IDA checkpoint or IDA MCP session

For legacy v1 review-seed mode only, also accept:

- `S04/s05-rw14-tpidr-offset-family-trace.json`
- `S04/s05-rw15-tpidr-writer-lifecycle-trace.json`
- `S04/s05-rw16-lifecycle-bridge-trace.json`
- `S04/s05-rw17-cross-function-arg-bridge.json`
- `S04/s05-rw18-convergence-gate.json`

## Workflow

1. Verify upstream readiness.
   - Require accepted S02-S04 and valid S05 worker outputs.
   - If any worker is blocked, emit service model with `s06_readiness: blocked`.
   - If S05 has `production_gate: blocked` but `review_seed_gate: ready`, run review-seed mode instead of failing the stage.
   - In review-seed mode, use `scripts/generate_s05_review_seed_service_model.py` to create S05 hypothesis-labelled artifacts from S04 RW14-RW18. Do not require VM/vCPU/Stage-2 production ownership links.

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
   - Do not propose lifecycle or HKIP names in S05.

## Outputs

Produce:

- `S05/service-model.json`
- `S05/ida-change-proposal.json`
- `S05/records/integrate-hypervisor-service-model.evidence.jsonl`
- `S05/records/integrate-hypervisor-service-model.decisions.jsonl`
- `S05/records/integrate-hypervisor-service-model.unknowns.jsonl`

## Boundaries

- Do not recover lifecycle, teardown completeness, or HKIP.
- Do not repair S05 ownership silently.
- Do not apply IDA writes directly.
- Do not use oracle, symbolized samples, source code, logs, DTB, or dynamic traces in production mode.
- Do not let large-model semantic guesses become confirmed service relationships. Label them `model_hypothesis`.

## S05 type and object propagation

This Skill performs type, structure, global object, and argument propagation as part of the unified workflow. Do not require or consume legacy review-seed files such as `S04/s05-rw15-*` or `S04/s05-rw17-*` unless a lab note explicitly asks for backward-compatibility analysis.

Use v2 inputs:

- `S02/functions.jsonl` or an equivalent IDA function export
- `S03/architecture-model.json` or sysreg/MMIO event export
- `S04/function-clusters.json`
- `S04/module-attribution.json`
- IDA decompile/disassembly evidence for clustered functions

Produce these primary artifacts:

- `S05/type-candidates.json`
- `S05/struct-layouts.jsonl`
- `S05/global-object-model.json`
- `S05/argument-flow.jsonl`
- `S05/ida-type-proposal.json`

Infer offset families, global roots, scalar/config/count globals, and cross-function argument roots. Separate confirmed layouts from hypotheses. Do not generate source code and do not use Oracle names as production evidence.

In corpus-wide mode, emit `S05/name-candidates.jsonl` for every clustered function. Prefer evidence-backed semantic names, otherwise use stable module-local names and keep addresses only in comments/source maps.
