---
name: recover-hypervisor-scheduler
description: "Recover S06 hypervisor scheduler candidates from accepted S05 runtime ownership evidence. Use when the workflow needs runqueue, runnable/block state, vCPU selection, affinity, timer wakeup, preemption, and world-switch scheduling paths without naming policy beyond evidence."
---

# Recover Hypervisor Scheduler

## Purpose

Recover static scheduler structure and vCPU selection evidence. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S05/runtime-object-model.json`
- `S05/types.jsonl`
- `S05/resource-ownership.jsonl`
- `S04/context-layouts.jsonl`
- `S04/architecture-events.jsonl`
- `S03/call-graph.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S05.
   - If runtime ownership is not accepted, emit `blocked_by_upstream`.

2. Find scheduling anchors.
   - Track runqueue-like lists, current/next vCPU references, affinity masks, timer/IRQ wakeups, locks, and world-switch calls.
   - Record state writes and comparisons before naming states.

3. Recover state transitions.
   - Emit candidate `state_0xN` values when names are unknown.
   - Distinguish runnable/block/preempt/wakeup candidates only with control-flow and data-write evidence.

4. Link to runtime objects.
   - Bind scheduler actions to vCPU/CPU/context candidates from S05.
   - Preserve ambiguous ownership as Unknown.

## Outputs

Produce:

- `S06/scheduler-model.json`
- `S06/state-machines.jsonl`
- `S06/records/recover-hypervisor-scheduler.evidence.jsonl`
- `S06/records/recover-hypervisor-scheduler.decisions.jsonl`
- `S06/records/recover-hypervisor-scheduler.unknowns.jsonl`

## Boundaries

- Do not recover VM config or interrupt routing tables.
- Do not infer fairness or policy names without evidence.
- Do not modify S05 ownership.
- Do not apply IDA writes directly.
