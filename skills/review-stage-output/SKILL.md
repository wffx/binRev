---
name: review-stage-output
description: "Independently review one Stage of the ARM64 EL2 Hypervisor Image recovery workflow. Use after artifact validation to assess evidence quality, unknown propagation, overclaiming, Stage exit conditions, IDA transaction safety, and whether the Stage should be accepted, reworked, or blocked."
---

# Review Stage Output

## Purpose

Review a completed Stage as an independent gate. This Skill does not participate in Producer reasoning for that Stage, does not fix artifacts, does not apply IDA changes, and does not replace the final human gate.

## Required context

Before reviewing, read only the relevant contract material:

- `specifications/workflow.md` for the target Stage goal, inputs, outputs, route, exit conditions, and boundary.
- `specifications/stage-audit.md` for audit expectations.
- `specifications/contracts/artifact-contracts.md` for evidence, decision, unknown, and review schemas.
- `specifications/contracts/constraint-boundary.md` for project-wide forbidden inputs, tools, and claims.
- `specifications/contracts/ida-tool-contract.md` for IDA-only restrictions when the Stage touches IDA.

## Inputs

Require:

- Target Stage ID.
- Accepted upstream Stage manifests and indexes required by the Stage contract.
- Current Stage candidate outputs.
- `Sxx/artifact-validation.json`.
- Producer evidence, decision, and unknown shards.
- IDA proposals and transaction records when the Stage uses IDA.

Review from frozen artifacts only. Do not rely on chat memory or unstored assumptions.

## Review workflow

1. Confirm validation readiness.
   - If `artifact-validation.json` is missing or not `pass`, recommend `rework` or `block` before reviewing technical quality.

2. Compare against the Stage contract.
   - Check the Stage goal describes exactly one state transition.
   - Verify outputs match the Stage's declared responsibility.
   - Flag artifacts that belong to later or earlier Stages.

3. Audit evidence quality.
   - Verify each conclusion has direct evidence or a clearly marked inference chain.
   - Distinguish binary facts, IDA observations, architecture-spec semantics, and business-background hypotheses.
   - Reject claims supported only by function-name appearance, generic open-source similarity, or plausible business naming.

4. Audit uncertainty.
   - Confirm unknowns are explicit, scoped, and propagated.
   - Flag confident names or types where the evidence supports only offset-first or candidate-level labels.
   - Ensure unresolved indirect control flow and security-relevant unknowns remain visible.

5. Audit IDA discipline.
   - For S02-S07, verify proposed IDA writes are reviewed, minimal, reversible, and tied to evidence.
   - Confirm Producer Skills did not directly commit shared IDA state.
   - For S08-S10, flag any new IDA mutation as out of bounds.
   - Do not require a separate human confirmation merely for IDA MCP connection, script execution, or transport invocation; review the proposal/transaction evidence instead.

6. Audit exit conditions.
   - Evaluate `accepted`, `rework`, and `blocked` conditions from the Stage contract.
   - Recommend the earliest responsible Stage for rework when a downstream symptom is caused upstream.
   - Treat normal low coverage or ordinary unknowns as acceptable unless they break downstream prerequisites.

7. Audit branch-validation quality when present.
   - Read only production Stage branch-validation artifacts derived from the target Image and IDA evidence.
   - Recommend `rework` when branch-level metrics show suspected false function starts, missed branch roots, merged functions, or boundary errors that would mislead downstream stages.
   - Do not allow IDA writeback success to compensate for poor branch-structure quality.
   - Do not use external symbol files as production Stage evidence.
   - If a local oracle IDB or symbolized IDB exists for forward-testing, require its outputs to live under `validation/oracle/` and mark every match `validation_only`. Oracle names may explain skill/workflow error, but must not become production names, evidence IDs, or accepted conclusions.

8. Audit S03 code/data-boundary quality when reviewing S03.
   - Require `S03/code-data-boundary-audit.json`.
   - Verify all IDA-visible unidentified bit/data/data-island ranges follow the current S03 policy. For the main `.text` body, require code-first recovery: ARM64 code or explicitly reviewed `.inst`/`instruction_fallback`, not silent qword/DCQ data islands.
   - Recommend `rework` or `block` if any structural code/data boundary unknown would be carried into S04.
   - Do not treat semantic uncertainty about a data object's final subsystem ownership as a code/data-boundary failure.

9. Audit boundary compliance.
   - Reject external symbols, source baselines, logs, DTBs, runtime traces, platform documentation, or non-IDA reverse tools.
   - Reject claims of original-source identity, runtime equivalence, complete buildability, or security proof.

## Output

Write `Sxx/stage-review.json` with:

- `stage_id`
- `case_id`
- `image_sha256`
- `review_result`: `accept`, `rework`, or `block`
- `summary`
- `contract_findings`
- `evidence_findings`
- `unknown_findings`
- `ida_findings`
- `boundary_findings`
- `required_rework`
- `blocked_reason`
- `human_gate_items`
- `reviewer_notes`

Use `accept` only as a recommendation. The human gate remains authoritative for Stages that require manual approval.

## Decision rules

- Recommend `accept` when the Stage meets its exit conditions, unknowns are explicit, and no high-impact contract violation remains.
- Recommend `rework` when artifacts are incomplete, evidence is weak, claims overreach, or an upstream artifact must be corrected.
- Recommend `block` only when the Stage cannot proceed without information, authority, or tools outside the fixed project boundary.

## Boundaries

- Do not edit Producer outputs.
- Do not apply IDA changes.
- Do not generate new reverse-engineering conclusions.
- Do not import oracle names or oracle symbol identities into production artifacts; oracle mapping is validation-only.
- Do not use review text to hide unresolved or unsafe assumptions.
- Do not accept a Stage solely because it is useful or plausible.
