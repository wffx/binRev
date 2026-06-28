---
name: recover-arm64-exception-model
description: "Recover S03 ARM64/EL2 exception vectors, vector slots, handlers, dispatch, save/restore, and return paths from IDA evidence. Use after S02 program structure when the workflow needs exception/trap roots for context and hypervisor architecture analysis."
---

# Recover ARM64 Exception Model

## Purpose

Build an exception model for ARM64 EL2 code. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It does not mutate IDA.

## Inputs

Require:

- `S02/stage-manifest.json`
- `S02/program-model.json`
- `S02/functions.jsonl`
- `S02/call-graph.json`
- `S02/unresolved-regions.jsonl`
- `S02/unresolved-regions*.jsonl` when rework iterations exist
- `S02/code-data-boundary-audit.json`
- `S03/boot-model.json` when available
- `S01/ida-baseline.i64`

## Workflow

1. Run the S02 gate preflight.
   - Read `S02/stage-manifest.json` and all available `S02/unresolved-regions*.jsonl`.
   - If S02 is not `accepted` or any unresolved code/data/blob record is blocking, run only in `forward_test_deferred_by_s03_rework` mode.
   - Do not treat vector or handler candidates inside blocking unresolved blob ranges as recovered roots.
   - Propagate overlapping unresolved ranges as `blocked_by_s02_unresolved_blob` Unknowns.

2. Connect to IDA read-only and record transport metadata.

3. Locate vector candidates.
   - Search for aligned tables/regions matching ARM64 vector-slot spacing.
   - Use branch density, exception return instructions, sysreg reads, and context save patterns.
   - Keep multiple candidates when alignment or base evidence conflicts.
   - Exclude S02 blocking unresolved ranges from acceptance; scan them only to produce rework evidence.
   - Consume S02 `unresolved-regions*.jsonl` records that were resolved as `embedded-vector-code-fragment`, `embedded-vector-branch-veneer-table`, or equivalent nonblocking vector classifications.
   - Treat repeated `0x80`-sized slots ending in direct branches as vector-slot evidence even when the region is not modeled as normal functions.
   - Treat branch veneers that route slots to save stubs as exception evidence; do not force veneers themselves into functions.

4. Classify slots and handlers.
   - Record slot address, slot kind candidate, branch target, fallthrough, and handler root.
   - Identify synchronous/IRQ/FIQ/SError-like groups only when instruction layout supports it.
   - Avoid importing architectural labels when slot order is not proven.
   - A handler root may be a local label or embedded code fragment rather than an IDA function start. Require target-only save/dispatch evidence before naming it a handler candidate.

5. Recover dispatch and return paths.
   - Track `ESR_EL2`, `FAR_EL2`, `HPFAR_EL2`, `ELR_EL2`, `SPSR_EL2` reads/writes.
   - Track `ERET`, `BR`, indirect dispatch, and no-return panic/wait paths.
   - Record unresolved indirect dispatch as Unknown, not as an invented handler.

6. Link to context-layout recovery.
   - Emit save/restore store/load offsets and register sets.
   - Mark asymmetry and incomplete restore paths.
   - Attach `s02_gate_status` and `unresolved_dependencies` to any context evidence whose handler boundary is not accepted.
   - Promote handler stubs with dense `STP`/`STR` saves plus `ELR_EL2`, `SPSR_EL2`, and `ESR_EL2` reads into context-layout input, even if IDA has not created a function at every stub start.

## Outputs

Produce:

- `S03/exception-model.json`
- `S03/records/recover-arm64-exception-model.evidence.jsonl`
- `S03/records/recover-arm64-exception-model.decisions.jsonl`
- `S03/records/recover-arm64-exception-model.unknowns.jsonl`

`exception-model.json` should include:

- `vector_candidates`
- `vector_slots`
- `handler_candidates`
- `dispatch_paths`
- `return_paths`
- `save_restore_observations`
- `unresolved_exception_edges`
- `s02_gate`
- `unresolved_dependencies`

## Boundaries

- Do not confirm VM exit reasons solely from ESR constants.
- Do not name guest/host context structures; emit offsets for S03 context integration.
- Do not assume Linux vector layout unless the target bytes support it.
- Do not apply IDA writes directly.
- Do not use external symbols, source code, logs, DTB, traces, or other reverse tools.
