---
name: integrate-program-structure
description: "Integrate S03 function, data-object, data-island, code/data-boundary, and indirect-control-flow outputs into a single program structure model. Use to resolve all unidentified bit/data conflicts, produce call graph and unresolved-region indexes, generate reviewed IDA change proposals, and gate whether S04 may start."
---

# Integrate Program Structure

## Purpose

Merge S03 worker outputs into a coherent program model and a minimal IDA change proposal. This Skill may propose candidate names or comments, but it does not write them to IDA directly.

This Skill may directly request read-only IDA/IDA MCP access to verify current state before producing a proposal. Do not ask for a separate human confirmation for read-only connection; all IDA mutations remain proposal-only and must be executed by `apply-reviewed-ida-changes`.

## Inputs

Require:

- `S03/functions.jsonl`
- `S03/data-objects.jsonl`
- `S03/data-islands.jsonl`
- `S03/code-data-boundary-audit.json`
- `S03/indirect-targets.jsonl`
- `S03/unresolved-regions.jsonl`
- `S02/address-space.json`
- `S02/ida-baseline-snapshot.json`

## Workflow

1. Merge functions and data.
   - Detect overlap or conflict.
   - Preserve conflict records rather than deleting evidence.
   - Keep auto-generated IDA names unless proposal evidence supports a candidate name.
   - Preserve branch-sample validation status from `recover-ida-functions`.
   - Treat every unclassified bit/data/data-island range as a blocking S03 issue until it is classified or explicitly blocked.
   - Treat middle `.text` data islands, qwords, and DCB/DCD arrays as blocking unless they were converted to code or to explicit `.inst`/`instruction_fallback` records. Do not accept them as literal pools by default.

2. Build call graph.
   - Direct calls from function recovery.
   - Indirect edges as candidate or unresolved.
   - External or unknown targets explicitly represented.

3. Produce program model.
   - Functions.
   - Data objects.
   - Call graph.
   - Indirect flow summary.
   - Unresolved regions and impact.

4. Generate IDA proposal.
   - Candidate names and comments only when evidence is clear.
   - Data-definition actions for literal pools, pointer tables, constant tables, strings, alignment, and embedded blobs must be included when needed to clean IDA-visible bit/data state.
   - Keep `candidate_` prefix unless reviewed evidence supports removal.
   - Include rollback information for every proposed edit.
   - Do not propose a rename for `false_function_start`, `boundary_miss`, or `merged_candidate` records unless the proposal explicitly marks the object as a boundary-rework placeholder.

5. Score branch quality.
   - Require at least one `branch_id` in S03 validation artifacts generated from target Image and IDA evidence.
   - Summarize boundary conflicts, suspected false starts, suspected merged functions, unresolved tail chunks, and candidate-name quality from production evidence only.
   - Set S03 to `rework` when branch-level deviation breaks downstream S04 root selection.

6. Enforce code/data boundary gate.
   - Require `code-data-boundary-audit.json` to show zero unclassified bit/data/data-island ranges before recommending S03 acceptance.
   - Require the main `.text` body to be code-first: decodable 4-byte words must be IDA code; undecodable words must be counted as `instruction_fallback` blockers or accepted-risk only after explicit review.
   - If any range is `blocking_unknown`, set S03 to `blocked` or `rework` and do not allow S04.
   - S03 may keep semantic Unknowns, but not structural code/data boundary Unknowns that affect IDA disassembly, CFG, literal use, or downstream architecture recovery.
   - Require point-level readback for user-reported addresses and representative data-island samples. A point inside a data item tail is acceptable only if the artifact records `item_head`, `item_end`, classification, and reviewable comment/name at the owning head.
   - Do not treat `is_unknown=false` alone as sufficient for S03 acceptance; require human-visible explanation for head/tail cases that would otherwise look unresolved in IDA.

## Outputs

Produce:

- `S03/program-model.json`
- `S03/call-graph.json`
- `S03/ida-change-proposal.json`
- `S03/records/integrate-program-structure.evidence.jsonl`
- `S03/records/integrate-program-structure.decisions.jsonl`
- `S03/records/integrate-program-structure.unknowns.jsonl`

## Boundaries

- Do not apply IDA changes.
- Do not infer EL2 architecture, VM, scheduler, HKIP, or interrupt semantics.
- Do not upgrade candidate names to confirmed names without review.
- Do not erase unresolved indirect-flow risks.
- Do not erase or downgrade structural code/data boundary problems into ordinary unresolved regions.
- Do not accept S03 solely because IDA comments or names were written successfully.
- Do not allow S04 to consume an IDA state with remaining unclassified bit/data/data-island ranges.
- Do not allow S04 to consume an IDA state where middle `.text` still contains qword/DCQ data islands or unreviewed `.inst` fallback blockers.
- Do not allow S04 to consume an IDA state where sampled/reported data-island points lack head/tail readback evidence.
- Do not read external symbol data or import external names into the production program model.
