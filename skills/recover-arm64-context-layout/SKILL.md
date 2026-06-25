---
name: recover-arm64-context-layout
description: "Recover S04 offset-first ARM64 context layouts for trap frames, vCPU context, per-CPU state, and save/restore areas. Use when boot or exception evidence contains register save/restore, stack-frame, or context-switch access patterns."
---

# Recover ARM64 Context Layout

## Purpose

Recover context layouts from save/restore evidence without importing source-level structs. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It does not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S03/functions.jsonl`
- `S03/unresolved-regions.jsonl`
- `S03/unresolved-regions*.jsonl` when rework iterations exist
- `S04/boot-model.json`
- `S04/exception-model.json`
- `S04/sysreg-accesses.jsonl` or `S04/architecture-events.jsonl` when available
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Run the S03/S04 gate preflight.
   - Read S03 stage status and unresolved blob ranges before clustering offsets.
   - If S03 is not `accepted`, or boot/exception inputs are forward-test only, mark context recovery `forward_test_deferred_by_s03_rework`.
   - Do not form persistent context layout claims from handlers or save/restore paths that overlap blocking unresolved code/data/blob ranges.
   - Keep affected offset clusters as Unknowns with `blocked_by_s03_unresolved_blob`.

2. Connect to IDA read-only and record transport metadata.

3. Collect layout evidence.
   - Stack-relative loads/stores around exception entry and return.
   - Base-register-relative loads/stores around context save/restore.
   - STP/LDP register pairs, STR/LDR general registers, FP/SIMD registers when visible.
   - System-register save/restore of `ELR_EL2`, `SPSR_EL2`, `SP_EL0`, `TPIDR_EL2`, timer/GIC state.
   - For exception vectors, accept save-stub labels and embedded code fragments as evidence sources when S04 exception recovery proves slot/veneer routing.
   - Prioritize stubs that save many GPR pairs and read `ELR_EL2`, `SPSR_EL2`, and `ESR_EL2`; these are strong exception-entry context layout seeds.

4. Cluster offsets.
   - Group by base register, function/path, direction, and register role.
   - Keep unknown base objects as `ctx_candidate_<addr>` or `base_reg_<Xn>`.
   - Separate stack frames from persistent context objects.

5. Infer minimal field candidates.
   - Emit field offsets, access width, source register, signedness only if evident.
   - Mark role as candidate: `gpr_save`, `sysreg_save`, `return_state`, `percpu_ref`, `vcpu_ref`, or `unknown`.
   - Detect overlapping or inconsistent access width as rework/unknown.

6. Feed S05 safely.
   - Produce offset-first records consumable by CPU/vCPU and Stage-2 recovery.
   - Do not assign final struct names or VM/vCPU ownership unless S05 confirms it.
   - If S03 or S04 is forward-test only, set downstream readiness to `blocked_by_s03_rework`.
   - If S03 is `review_required_after_rw5` with zero blocking unresolved blobs, mark output as `forward_test_review_required_after_s03_rw5` rather than `blocked_by_s03_rework`.

## Outputs

Produce:

- `S04/context-layouts.jsonl`
- `S04/records/recover-arm64-context-layout.evidence.jsonl`
- `S04/records/recover-arm64-context-layout.decisions.jsonl`
- `S04/records/recover-arm64-context-layout.unknowns.jsonl`

Each context-layout record should include:

- `layout_id`
- `base_evidence`
- `access_sites`
- `offset`
- `width`
- `register_or_sysreg`
- `direction`
- `candidate_role`
- `confidence`
- `conflicts`
- `s03_gate_status`
- `unresolved_dependencies`
- `downstream_readiness`

## Boundaries

- Do not import external struct definitions.
- Do not convert offset clusters into final C structs in S04.
- Do not decide CPU/vCPU/VM ownership; that belongs to S05.
- Do not apply IDA writes directly.
- Do not hide asymmetric or partially recovered save/restore paths.
