---
name: integrate-el2-architecture-model
description: "Integrate S04 boot-flow, exception-model, context-layout, sysreg, and architecture-event outputs into a single ARM64 EL2 architecture model. Use to detect conflicts, produce S05-consumable architecture artifacts, and generate reviewed IDA proposals without applying them."
---

# Integrate EL2 Architecture Model

## Purpose

Merge S04 worker outputs into one architecture model and a minimal IDA proposal. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S03/code-data-boundary-audit.json`
- `S03/unresolved-regions.jsonl`
- `S03/unresolved-regions*.jsonl` when rework iterations exist
- `S04/boot-model.json`
- `S04/exception-model.json`
- `S04/context-layouts.jsonl`
- `S04/sysreg-accesses.jsonl`
- `S04/architecture-events.jsonl`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/call-graph.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce the S03 cleanliness gate.
   - Read S03 status and all unresolved-region files before merging S04 outputs.
   - If S03 is not `accepted`, or if any unresolved record with `blocking: true` remains, set S04 model status to `forward_test_deferred_by_s03_rework`.
   - In that state, set `s05_readiness.status` to `blocked_by_s03_rework`, keep all IDA changes proposal-only, and do not emit an accepted `S04/ida-stage.i64`.
   - If S03 is `accepted` with residual `accepted-risk`, do not block S04/S05 solely for those waived records. Set S05 readiness to `ready_with_accepted_risks`, include the accepted-risk artifact in input provenance, and downgrade any S04 conclusion directly depending on a waived address to `inferred` or `unresolved`.
   - Treat unresolved code/data/blob ranges as hard exclusions for architecture roots unless the root is explicitly marked as blocked evidence for S03 rework.
   - If S03 is `review_required_after_rw5` and all unresolved records are nonblocking, allow a new S04 forward-test rerun with `model_status: forward_test_review_required_after_s03_rw5`; keep S05 readiness blocked until S03 and S04 are accepted.

2. Verify inputs and connect to IDA read-only when cross-checking current state.

3. Merge architecture roots.
   - Link boot roots, exception roots, context save/restore roots, and sysreg-heavy functions.
   - Preserve S03 boundary warnings that affect S04 conclusions.
   - Do not integrate a function as architecture root if its boundary is marked false-start or merged without a reviewed correction.
   - Do not integrate roots that overlap blocking S03 unresolved blobs as production architecture roots.
   - Integrate nonblocking vector-slot and veneer classifications as exception architecture roots when S04 exception evidence proves aligned slots, branch veneers, and save stubs.

4. Resolve conflicts.
   - Boot vs exception root overlap.
   - Context offset width/type conflicts.
   - Sysreg semantics that contradict the proposed function role.
   - Missing barrier/TLBI around page-table/TTBR changes.

5. Build S05-facing model.
   - `boot`
   - `exception`
   - `context_layout_refs`
   - `sysreg_index`
   - `architecture_event_index`
   - `candidate_runtime_anchors`
   - `blocking_unknowns`

6. Generate IDA proposal.
   - Propose candidate comments/names/types only after evidence IDs are attached.
   - Keep names architecture-level: boot, exception, context, sysreg, MMU, trap.
   - Do not propose VM, scheduler, interrupt-route, lifecycle, or HKIP names in S04.
   - Mark high-risk function boundary changes as review-only.
   - When S03 is not accepted, mark the transaction `proposal_only_not_applied` with `blocked_by_s03_rework`.

## Outputs

Produce:

- `S04/architecture-model.json`
- `S04/ida-change-proposal.json`
- `S04/records/integrate-el2-architecture-model.evidence.jsonl`
- `S04/records/integrate-el2-architecture-model.decisions.jsonl`
- `S04/records/integrate-el2-architecture-model.unknowns.jsonl`

`architecture-model.json` should include:

- `architecture_roots`
- `boot_model_ref`
- `exception_model_ref`
- `context_layout_refs`
- `sysreg_access_refs`
- `architecture_event_refs`
- `runtime_anchor_candidates`
- `s05_readiness`
- `s03_gate`
- `unresolved_dependencies`
- `rework_triggers`

## Boundaries

- Do not apply IDA changes.
- Do not repair S03 boundaries silently; emit rework when S04 evidence invalidates S03.
- Do not assign VM config, scheduler, interrupt, lifecycle, or HKIP ownership.
- Do not upgrade candidate names to confirmed names without review.
- Do not use external symbols, source code, logs, DTB, traces, or non-IDA reverse tools.
