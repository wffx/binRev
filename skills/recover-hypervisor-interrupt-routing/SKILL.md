---
name: recover-hypervisor-interrupt-routing
description: "Recover S06 interrupt routing candidates from accepted ARM64 EL2 and runtime evidence. Use when the workflow needs physical IRQ, virtual IRQ, VM/vCPU route, GIC/ICH/ICC-style register use, injection, EOI, maintenance, teardown, or passthrough evidence."
---

# Recover Hypervisor Interrupt Routing

## Purpose

Recover interrupt routing and virtual interrupt delivery candidates. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S05/runtime-object-model.json`
- `S05/resource-ownership.jsonl`
- `S04/sysreg-accesses.jsonl`
- `S04/architecture-events.jsonl`
- `S03/data-objects.jsonl`
- `S03/call-graph.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S05.
   - If interrupt-relevant architecture events are absent, emit absent/unknown rather than guessing.

2. Identify interrupt anchors.
   - Track GIC/ICH/ICC-like sysregs, distributor/redistributor-like MMIO, route tables, masks, and maintenance handlers.
   - Keep raw register/MMIO addresses as evidence.

3. Recover routing candidates.
   - Link physical IRQ to virtual IRQ and VM/vCPU only with table writes, injection paths, or teardown paths.
   - Track EOI, deactivate, migration, and passthrough-like paths as candidates.

4. Preserve safety constraints.
   - Record routes with missing VM/vCPU binding as blocking Unknowns.

## Outputs

Produce:

- `S06/interrupt-model.json`
- `S06/records/recover-hypervisor-interrupt-routing.evidence.jsonl`
- `S06/records/recover-hypervisor-interrupt-routing.decisions.jsonl`
- `S06/records/recover-hypervisor-interrupt-routing.unknowns.jsonl`

## Boundaries

- Do not claim a specific GIC/SMMU version without register-level evidence.
- Do not recover scheduler or lifecycle semantics.
- Do not modify runtime ownership.
- Do not apply IDA writes directly.
