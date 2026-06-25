---
name: recover-arm64-boot-flow
description: "Recover S04 ARM64/EL2 boot flow from an accepted S03 program model and IDA checkpoint. Use when the workflow needs entry-path, primary/secondary CPU init, MMU-enable handoff, wait/fail path, boot-time register setup, and boot-root evidence for an unsigned ARM64 Image."
---

# Recover ARM64 Boot Flow

## Purpose

Build the S04 boot model from target Image and IDA evidence. This Skill may directly open/read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/call-graph.json`
- `S03/indirect-targets.jsonl`
- `S03/unresolved-regions.jsonl`
- `S03/unresolved-regions*.jsonl` when rework iterations exist
- `S03/code-data-boundary-audit.json`
- `S03/ida-stage.i64` or the current accepted IDA checkpoint
- `S02/address-space.json`

## Workflow

1. Run the S03 gate preflight.
   - Read `S03/stage-manifest.json` before selecting roots.
   - If S03 status is not `accepted`, or if any `S03/unresolved-regions*.jsonl` record has `blocking: true`, run only in `forward_test_deferred_by_s03_rework` mode.
   - In forward-test mode, produce evidence and proposals for workflow tuning, but do not mark S04 as accepted, do not claim S05 readiness, and do not treat S03 rework records as authoritative program structure.
   - Load unresolved blob ranges and exclude them from boot-root selection unless the output explicitly records the root as `blocked_by_s03_unresolved_blob`.

2. Connect to IDA read-only.
   - Prefer native IDA MCP when available; otherwise use the configured `ida-mcp.exe` adapter.
   - Do not ask the user for confirmation before read-only connection.
   - Record transport, IDB path, read-only/writeable mode, and failures in evidence.

3. Select boot roots from S03.
   - Start from entry/root candidates, reset-like ranges, vector-adjacent blocks, and branch samples.
   - Treat S03 `review_required` or `rework` records as constraints, not as accepted truth.
   - Reject any root that overlaps a blocking unresolved code/data/blob range unless the goal is to explain that unresolved dependency.
   - Do not promote a suspected false function start into a boot root.

4. Recover boot phases.
   - Entry masking and early register setup: `DAIF`, `SPSel`, stack setup, zeroing, branch handoff.
   - Exception level checks: `CurrentEL`, `HCR_EL2`, `SCTLR_EL2`, `TCR_EL2`, `MAIR_EL2`.
   - Primary/secondary CPU split: MPIDR, parking loops, WFE/WFI, per-CPU paths.
   - MMU enable handoff: TTBR writes, TLBI, IC invalidation, barriers, manual-LR transitions.
   - Fail/wait paths: distinguish no-return wait loops from normal continuation labels.

5. Emit offset-first evidence.
   - Use addresses and instruction facts before semantic names.
   - Use candidate names such as `candidate_primary_boot_root` only after boundary evidence is explicit.
   - Keep manual-LR handoff and shared tail blocks explicit.
   - Attach `s03_gate_status` and `unresolved_dependencies` to boot paths affected by S03 rework.

6. Produce an IDA proposal only when useful.
   - Candidate comments/names may be proposed.
   - Function/chunk edits require `review_required` and must be executed only by `apply-reviewed-ida-changes`.
   - If S03 is not accepted, mark the proposal `proposal_only_not_applied` and `blocked_by_s03_rework`.

## Outputs

Produce:

- `S04/boot-model.json`
- `S04/records/recover-arm64-boot-flow.evidence.jsonl`
- `S04/records/recover-arm64-boot-flow.decisions.jsonl`
- `S04/records/recover-arm64-boot-flow.unknowns.jsonl`

`boot-model.json` should include:

- `boot_roots`
- `primary_cpu_path`
- `secondary_cpu_path`
- `mmu_enable_paths`
- `wait_or_fail_paths`
- `manual_lr_handoffs`
- `boot_register_events`
- `dependencies_on_s03_boundaries`
- `s03_gate`
- `unresolved_dependencies`
- `ida_proposal_refs`

## Boundaries

- Do not recover VM config, scheduler, interrupt routing, lifecycle, or HKIP.
- Do not use external symbols, source code, DTB, logs, or dynamic traces.
- Do not apply IDA writes directly.
- Do not equate Linux/Xen-like strings with source identity.
- Do not name lifecycle states; boot phases are architecture phases only.
