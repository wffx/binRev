---
name: recover-hypervisor-interrupt-routing
description: "Recover S05 interrupt routing candidates from accepted ARM64 EL2 and runtime evidence. Use when the workflow needs physical IRQ, virtual IRQ, VM/vCPU route, GIC/ICH/ICC-style register use, injection, EOI, maintenance, teardown, or passthrough evidence."
---

# Recover Hypervisor Interrupt Routing

## Purpose

Recover interrupt routing and virtual interrupt delivery candidates. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S04/runtime-object-model.json`
- `S04/resource-ownership.jsonl`
- `S03/sysreg-accesses.jsonl`
- `S03/architecture-events.jsonl`
- `S02/data-objects.jsonl`
- `S02/call-graph.json`
- `S04/ida-stage.i64`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S02-S04.
   - If interrupt-relevant architecture events are absent, emit absent/unknown rather than guessing.

2. Identify interrupt anchors.
   - Track GIC/ICH/ICC-like sysregs, distributor/redistributor-like MMIO, route tables, masks, and maintenance handlers.
   - Keep raw register/MMIO addresses as evidence.
   - **String xref enumeration**: 对中断相关证据字符串执行 `ida_xrefs_to_string`，**必须遍历全部 xref**，找唯一包含函数。
   - **Call graph propagation**: 对于每个包含 ICH_LR 或 GIC/ICC 寄存器访问的锚点函数，遍历其直接 callees，赋予中断域前缀命名：
     - `candidate_vgic_*` (vGIC 维护相关)
     - `candidate_irq_*` (通用中断处理)
   - 传播深度 1 层，与其他 domain 共享的 callee 标记为未决。

3. Recover routing candidates.
   - Link physical IRQ to virtual IRQ and VM/vCPU only with table writes, injection paths, or teardown paths.
   - Track EOI, deactivate, migration, and passthrough-like paths as candidates.

4. Preserve safety constraints.
   - Record routes with missing VM/vCPU binding as blocking Unknowns.

## Outputs

Produce:

- `S05/interrupt-model.json`
- `S05/records/recover-hypervisor-interrupt-routing.evidence.jsonl`
- `S05/records/recover-hypervisor-interrupt-routing.decisions.jsonl`
- `S05/records/recover-hypervisor-interrupt-routing.unknowns.jsonl`

## Boundaries

- Do not claim a specific GIC/SMMU version without register-level evidence.
- Do not recover scheduler or lifecycle semantics.
- Do not modify runtime ownership.
- Do not apply IDA writes directly.
