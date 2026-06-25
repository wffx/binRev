---
name: integrate-hypervisor-service-model
description: "Integrate S06 VM config, scheduler, and interrupt-routing outputs into a unified hypervisor service model. Use to reconcile VM/vCPU/device/IRQ references, state machines, service relationships, blocking conflicts, and reviewed IDA proposals without applying them."
---

# Integrate Hypervisor Service Model

## Purpose

Merge S06 service workers into a S07-consumable service model. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S06/vm-config-model.json`
- `S06/scheduler-model.json`
- `S06/interrupt-model.json`
- `S06/state-machines.jsonl`
- `S05/runtime-object-model.json`
- `S05/resource-ownership.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Verify upstream readiness.
   - Require accepted S03-S05 and valid S06 worker outputs.
   - If any worker is blocked, emit service model with `s07_readiness: blocked`.

2. Reconcile references.
   - Link VM, vCPU, CPU, device, IRQ, and memory-region references.
   - Detect conflicting ownership, route targets, or state transitions.

3. Build service model.
   - Preserve config, scheduler, and interrupt submodels as references.
   - Emit unified state-machine candidates and blocking unknowns.

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
