---
name: validate-artifact-contract
description: "Validate Stage input and output artifacts for the ARM64 EL2 Hypervisor Image recovery workflow. Use before any Stage review or acceptance to check schema shape, case identity, Image SHA-256, producer ownership, source artifact hashes, evidence references, unknown records, and path constraints."
---

# Validate Artifact Contract

## Purpose

Validate that a Stage artifact set is safe to pass to review or downstream Skills. This Skill is a gatekeeper only: it does not repair artifacts, infer reverse-engineering facts, modify IDA, or advance workflow state.

## Required context

Before validating a Stage, read only the relevant contract material:

- `specifications/workflow.md` for the target Stage contract.
- `specifications/contracts/artifact-contracts.md` for artifact envelopes, evidence, decisions, unknowns, and validation output.
- `specifications/contracts/constraint-boundary.md` when a field may conflict with the single-binary, IDA-only boundary.

## Inputs

Require the caller to provide or identify:

- Target Stage ID, for example `S04`.
- `stages/S00/case-manifest.json`.
- `stages/S00/constraint-profile.json`.
- `workflow/workflow-state.json`.
- All mandatory Stage inputs listed in the Stage contract.
- All candidate Stage outputs listed in the Stage contract.
- All producer record shards for the Stage:
  - `records/<producer>.evidence.jsonl`
  - `records/<producer>.decisions.jsonl`
  - `records/<producer>.unknowns.jsonl`

If a path convention differs in a case workspace, use the workspace manifest rather than guessing.

## Validation workflow

1. Check case identity.
   - Verify every artifact carries the same Case ID.
   - Verify every artifact that references the binary uses the `Image` SHA-256 from `case-manifest.json`.
   - Reject artifacts that silently omit Case ID or binary hash when the contract requires them.

2. Check Stage contract completeness.
   - Confirm every required input exists.
   - Confirm every required output exists.
   - Confirm required shared outputs exist: `stage-manifest.json`, `artifact-validation.json`, `stage-review.json` if validating post-review, record shards, and Stage indexes.
   - Treat missing allowed-unknown fields as a validation issue unless the Stage contract explicitly permits absence.

3. Check ownership.
   - Verify each artifact is produced by its unique Owner Skill from `skill-architecture.md`.
   - Reject outputs produced by a non-owner Skill.
   - Reject direct edits to upstream accepted artifacts.

4. Check evidence and decision references.
   - For every technical claim, require at least one Evidence ID or Decision ID.
   - Verify referenced IDs exist in the Stage indexes or producer shards.
   - Verify evidence points to allowed sources: the single `Image`, accepted artifacts, or IDA artifacts allowed by the current Stage.
   - Flag claims backed only by business background as invalid evidence.

5. Check unknown handling.
   - Verify unresolved, ambiguous, absent, or blocked facts are written to unknown records.
   - Verify unknown records include impact scope and downstream propagation notes when they affect later Stages.
   - Reject artifacts that replace unknowns with confident prose.

6. Check IDA transaction discipline.
   - For S02-S07, verify any IDA mutation has a proposal, review result, transaction record, and before/after reference.
   - For S08-S10, reject any new IDA write proposal.
   - For Stages that do not use IDA, reject IDA-derived claims unless they come from accepted upstream artifacts.

7. Check boundary compliance.
   - Reject references to external source trees, symbol files, logs, DTBs, platform documentation, dynamic traces, or non-IDA reverse-engineering tools.
   - Reject claims of original source recovery, runtime equivalence, buildability, or security proof unless the workflow contract explicitly allows that statement.

## Output

Write `Sxx/artifact-validation.json` with:

- `stage_id`
- `case_id`
- `image_sha256`
- `validated_at`
- `result`: `pass`, `fail`, or `blocked`
- `checked_artifacts`
- `missing_artifacts`
- `schema_issues`
- `ownership_issues`
- `evidence_issues`
- `unknown_issues`
- `ida_transaction_issues`
- `boundary_issues`
- `recommended_next_state`: `review_ready`, `rework`, or `blocked`

Also append validation evidence, decisions, and unknowns to this Skill's Stage record shards when the workflow requires record shards for validators.

## Decision rules

- Return `pass` only when all mandatory artifacts exist and no contract, ownership, evidence, unknown, IDA, or boundary issue remains.
- Return `fail` when the issue is correctable within the current or upstream Stage.
- Return `blocked` only when validation requires information or authority forbidden by the project boundary.

## Boundaries

- Do not repair artifacts.
- Do not infer missing reverse-engineering facts.
- Do not modify IDA.
- Do not mark a Stage accepted.
- Do not override the reviewer or human gate.
- Do not downgrade validation failures because a later Stage might compensate.
