---
name: apply-reviewed-ida-changes
description: "Apply already-reviewed IDA change proposals for the ARM64 EL2 Hypervisor Image recovery workflow. Use only in S02-S07 after review or human approval to transactionally create functions, segments, data items, arrays, structures, enums, prototypes, names, comments, or source mappings in IDA, while recording before/after state and rollback information."
---

# Apply Reviewed IDA Changes

## Purpose

Apply authorized IDA changes as a transaction executor. This Skill is deliberately mechanical: it does not invent names, types, comments, function boundaries, or business semantics.

Connecting to IDA/IDA MCP and executing the IDA transaction transport does not require separate human confirmation. The gate for this Skill is the reviewed proposal or oracle-assisted auto-review decision plus the workflow transaction record and rollback/pre-state requirements.

## Required context

Before applying changes, read only the relevant contract material:

- `specifications/workflow.md` for the current Stage route and human gate requirements.
- `specifications/contracts/ida-tool-contract.md` for allowed IDA operations and forbidden tools.
- `specifications/contracts/artifact-contracts.md` for proposal, transaction, evidence, and snapshot records.
- `specifications/contracts/constraint-boundary.md` for project-wide tool and claim boundaries.

## Inputs

Require:

- Target Stage ID from S02 through S07.
- Accepted IDA checkpoint or baseline for the Stage.
- Reviewed `ida-change-proposal` artifact.
- Review result authorizing the proposal.
- Human approval record when the workflow route requires a human gate.
- Current Case ID and `Image` SHA-256.

Reject execution if any proposal item lacks evidence, review status, operation kind, target address/object, expected pre-state, and rollback data.

## Allowed operations

Apply only reviewed operations that IDA or IDAPython can perform:

- Create or adjust segment metadata.
- Create function boundaries.
- Create code, data items, strings, arrays, tables, structures, enums, or prototypes.
- Rename functions, globals, labels, fields, or types.
- Apply comments, repeatable comments, or source mapping annotations.
- Apply type information that was approved by the Stage review.

When Hex-Rays is available, re-decompile affected functions only to compare quality and detect breakage. Do not treat prettier pseudocode as evidence by itself.

## Transaction workflow

1. Preflight.
   - Confirm Stage is S02-S07.
   - Confirm the proposal is reviewed and, when required, human-approved.
   - Confirm the IDA database matches the proposal's expected source checkpoint.
   - Confirm the proposal does not include unreviewed or speculative operations.
   - Confirm the IDA transport can open the IDB before any mutation. If `open_idb` fails, times out, or reports headless/batch/license failure, record `failed_before_ida_script_execution` and do not infer success from file timestamp or hash changes.

2. Capture pre-state.
   - Record target addresses, names, types, comments, segment properties, function boundaries, xrefs, and decompiler status if available.
   - Record enough data to rollback or manually reconstruct the prior state.

3. Apply changes atomically by proposal group.
   - Apply deterministic, low-level changes first: segments, code/data, functions.
   - Apply types and names after address and object existence is stable.
   - Apply comments and source mappings last.
   - Stop the group on first unexpected pre-state mismatch.

4. Capture post-state.
   - Snapshot affected objects.
   - Re-run local IDA analysis only where permitted by the proposal.
   - Re-decompile affected functions if Hex-Rays exists and the proposal asks for quality comparison.

5. Record transaction.
   - Write success, partial, failed, or rolled-back status.
   - Include every applied operation, skipped operation, failure reason, and rollback action.
   - Preserve proposal IDs and Evidence IDs.

6. Verify committed state.
   - Treat a transaction as `success` only after `save_database` succeeds and a readback snapshot confirms the expected affected objects.
   - If the IDB hash changes but no post-state readback exists, mark the IDB checkpoint as dirty/untrusted for that iteration and keep the Stage in `rework_required`.
   - Never promote a Stage or proposal based solely on a timed-out MCP call, partial console output, residual MCP server state, or old comments/names found in the IDB file.
   - For data-island cleanup, verify both the requested address and its owning item head. If the requested address is a tail, record the head/end mapping and ensure the owning head carries the reviewed classification comment.

## Output

Append to the Stage IDA transaction log, normally `Sxx/ida-change-transactions.jsonl`, with:

- `transaction_id`
- `stage_id`
- `case_id`
- `image_sha256`
- `source_checkpoint`
- `proposal_id`
- `review_id`
- `human_approval_id`
- `operations_applied`
- `operations_skipped`
- `pre_state`
- `post_state`
- `rollback`
- `result`: `success`, `partial`, `failed`, or `rolled_back`
- `affected_ida_objects`
- `affected_artifacts`

Do not create the final Stage checkpoint directly unless the workflow contract assigns that to this Skill. In the current workflow, `snapshot-ida-analysis-state` owns versioned `.i64` and normalized JSON snapshots.

## Failure handling

- If pre-state does not match, stop before mutation and return `failed`.
- If `open_idb` fails before the IDAPython transaction runs, append a failed transaction record with `actions_committed: 0`, `save_database_result: false`, and `verified_by_reopen: false`.
- If an operation fails after prior operations succeeded, rollback the group when rollback data is sufficient; otherwise mark `partial` and require human review.
- If IDA or IDAPython is unavailable, return `blocked` through the transaction artifact and do not emulate IDA with another tool.
- If the transport times out and the IDB hash later changes, do not assume the intended mutation succeeded. Create a failure/dirty-state artifact, then require explicit readback verification before any downstream Stage may consume that IDB.

## Boundaries

- Do not propose changes.
- Do not reinterpret binary semantics.
- Do not apply unreviewed names, types, comments, or function boundaries.
- Do not use Ghidra, Binary Ninja, objdump, QEMU, Unicorn, debugger traces, external symbols, or external source code.
- Do not apply IDA writes in S00, S01, or S08-S10.
