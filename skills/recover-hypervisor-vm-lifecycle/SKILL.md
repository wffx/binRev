---
name: recover-hypervisor-vm-lifecycle
description: "Recover S06 VM lifecycle candidates from accepted S05 service and S04 ownership evidence. Use when the workflow needs create, load, start, pause, resume, reset, destroy, error rollback, VMID/page/IRQ/CPU-binding resource transitions, and lifecycle state machines."
---

# Recover Hypervisor VM Lifecycle

## Purpose

Recover VM lifecycle and resource transition candidates. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

If upstream S06 is `review_seed_ready_production_blocked`, operate in review-seed mode: carry forward only explicitly labelled `model_hypothesis` lifecycle seeds and keep VM create/load/start/pause/resume/reset/destroy semantics unknown unless binary/IDA evidence proves VM/vCPU/resource identity.

## Inputs

Require:

- `S05/service-model.json`
- `S05/state-machines.jsonl`
- `S04/resource-ownership.jsonl`
- `S04/runtime-object-model.json`
- `S03/call-graph.json`
- `S05/ida-stage.i64`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S05.
   - If S06 is review-seed-only, do not fail the workflow; emit `review_seed_only` outputs and block production lifecycle.
   - If service references are not stable, emit `blocked_by_upstream`.

2. Identify lifecycle anchors.
   - Track allocation, initialization, load, start, stop, reset, destroy, rollback, and cleanup paths.
   - Keep unknown states as `state_0xN`.
   - **String xref enumeration（字符串交叉引用全量枚举）**: 对本阶段相关的每个证据字符串（`domain_crash`, `Freed init memory`, `Failed to free P2M`, `Scrubbing Free RAM`, `Domain heap initialised` 等），执行 `ida_xrefs_to_string` 获取所有 xref 地址，然后对每个 xref 找包含函数并去重。**必须遍历全部 xref，不得只取前几个**。每个唯一包含函数若未被其他 domain（vCPU/Stage-2/scheduler/interrupt/HKIP）声明，则赋予生命周期域前缀命名（`candidate_domain_*`）。
   - **Call graph propagation（调用图传播）**: 对每个已命名的生命周期锚点函数，遍历其直接 callees（BL 指令目标）。若 callee 未被其他 domain 声明，赋予 `candidate_domain_*` 命名。传播深度 1 层。

3. Track resource transitions.
   - Record VMID, page ownership, IRQ route, CPU/vCPU binding, and context changes per transition.
   - Mark missing cleanup evidence as Unknown.
   - In review-seed mode, do not record VMID/page/IRQ/CPU-binding transitions as facts; record them only as missing resource identity blockers.

## Outputs

Produce:

- `S06/lifecycle-model.json`
- `S06/resource-transitions.jsonl`
- `S06/records/recover-hypervisor-vm-lifecycle.evidence.jsonl`
- `S06/records/recover-hypervisor-vm-lifecycle.decisions.jsonl`
- `S06/records/recover-hypervisor-vm-lifecycle.unknowns.jsonl`

## Boundaries

- Do not claim security invariants; integration and S08 audit own invariant checks.
- Do not infer lifecycle names from common hypervisor terminology alone.
- Do not convert per-CPU/static context sequences into VM lifecycle transitions without owner/resource closure.
- Do not apply IDA writes directly.
