---
name: recover-hypervisor-scheduler
description: "Recover S05 hypervisor scheduler candidates from accepted S04 runtime ownership evidence. Use when the workflow needs runqueue, runnable/block state, vCPU selection, affinity, timer wakeup, preemption, and world-switch scheduling paths without naming policy beyond evidence."
---

# Recover Hypervisor Scheduler

## Purpose

Recover static scheduler structure and vCPU selection evidence. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S04/runtime-object-model.json`
- `S04/types.jsonl`
- `S04/resource-ownership.jsonl`
- `S03/context-layouts.jsonl`
- `S03/architecture-events.jsonl`
- `S02/call-graph.json`
- `S04/ida-stage.i64`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S02-S04.
   - If runtime ownership is not accepted, emit `blocked_by_upstream`.

2. Find scheduling anchors.
   - Track runqueue-like lists, current/next vCPU references, affinity masks, timer/IRQ wakeups, locks, and world-switch calls.
   - **String xref enumeration**: 对每个调度器证据字符串（`csched2_global_init`, `do_schedule`, `switch_sched`, `csched2_res_pick`, `cpu_add_to_runqueue`, `credit2_runqueue`, `Initializing Credit2 scheduler` 等）执行 `ida_xrefs_to_string`，**必须遍历全部 xref**，找所有唯一包含函数。赋予 `candidate_sched_*` / `candidate_scheduler_*` 命名。
   - **Call graph propagation**: 对每个已命名的调度器锚点，遍历直接 callees。传播深度 1 层。

3. Recover state transitions.
   - Emit candidate `state_0xN` values when names are unknown.
   - Distinguish runnable/block/preempt/wakeup candidates only with control-flow and data-write evidence.

4. Link to runtime objects.
   - Bind scheduler actions to vCPU/CPU/context candidates from S04.
   - Preserve ambiguous ownership as Unknown.

## Outputs

Produce:

- `S05/scheduler-model.json`
- `S05/state-machines.jsonl`
- `S05/records/recover-hypervisor-scheduler.evidence.jsonl`
- `S05/records/recover-hypervisor-scheduler.decisions.jsonl`
- `S05/records/recover-hypervisor-scheduler.unknowns.jsonl`

## Boundaries

- Do not recover VM config or interrupt routing tables.
- Do not infer fairness or policy names without evidence.
- Do not modify S05 ownership.
- Do not apply IDA writes directly.
