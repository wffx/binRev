---
name: recover-ida-functions
description: "Recover function boundaries and direct call relationships from an accepted IDA checkpoint in the ARM64 EL2 Hypervisor Image workflow. Use in S03 to export function candidates, callers, callees, entry evidence, boundary confidence, and unresolved boundary issues without assigning high-level business semantics."
---

# Recover IDA Functions

## Purpose

Build the S03 function model from IDA evidence. This Skill may read IDA/MCP state and propose IDA changes, but it does not directly commit names, types, comments, or function boundaries.

Read-only IDA MCP connection is allowed as a normal Skill action and does not require separate human confirmation. Function creation, deletion, chunk surgery, renaming, comments, and type writes must remain proposal-only here.

## Inputs

Require:

- `S02/ida-baseline-snapshot.json`
- `S02/address-space.json`
- `S01/region-map.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enumerate IDA functions.
   - Record address, current IDA name, size, segment, and flags when available.
   - Mark IDA auto names as neutral evidence, not confirmed semantics.

2. Capture boundary evidence.
   - Entry candidate relation.
   - Direct branch/call targets.
   - Prologue/epilogue or noreturn hints.
   - Incoming xrefs and fallthrough/tail-call ambiguity.

3. Capture direct relationships.
   - Callers.
   - Callees.
   - Basic block count when available.
   - Unresolved outgoing edges.

4. Assign confidence.
   - `confirmed`: stable IDA function with clear entry and bounded control flow.
   - `candidate`: IDA function exists but boundary or role remains ambiguous.
   - `unknown`: range needs later recovery or may be inline data.

5. Select one branch sample for S03 validation.
   - Pick an entry-adjacent or architecture-visible root function and include its direct callees, branch targets, tail chunks, and unresolved indirect sites.
   - Record `branch_id`, root address, covered address range, selected nodes, and why this branch is representative.
   - Do not accept S03 from isolated single-function edits; at least one branch-level structure must be auditable.

6. Validate boundary quality before naming.
   - Treat a candidate that starts inside a suspected parent/tail chunk as `boundary_rework`, not as a nameable function.
   - Treat a function that contains multiple branch-local candidate entries as `merged_candidate`, not as a final boundary.
   - If branch validation reports `false_function_start`, `boundary_miss`, or `merged_functions`, emit rework decisions before proposing IDA names.
   - Use only target Image and IDA-derived evidence during production recovery.

7. Handle large structural blockers range-first.
   - For mixed or unowned-code ranges, do not decide from a single proposed address. Enumerate candidate entries across the whole range, then separate ordinary function candidates from embedded code/data blobs, patch tables, alternatives, vectors, and alignment islands.
   - Treat ARM64 exception-vector slots and branch veneer tables as embedded code fragments when they consist of aligned slots that branch into real handlers. Do not force every vector slot or veneer into a normal function.
   - Split compact multi-function blobs boundary-first when target-only control flow shows multiple bounded functions separated by data/alignment or no-return error paths.
   - In forward-test only, an oracle/symbol IDB may be used to tune confidence, but production artifacts must not depend on oracle names or symbols.
   - If an oracle or heuristic candidate does not form a stable target function with matching readback boundaries, clean up any temporary candidate name/function and record the range as unresolved instead of leaving a misleading partial recovery.
   - Use generic names such as `candidate_recovered_code_<addr>` for applied forward-test candidates; keep oracle/source names only in validation artifacts.
   - A remaining structural range must be explicit: `unresolved-code-data-blob`, `embedded-code-fragment`, `data-island`, `alignment`, or another reviewed class. Silent IDA bit/data ambiguity is not acceptable input to S04.

8. In forward-test labs, use a symbolized oracle only as a convergence check.
   - If a paired oracle IDB exists, compare by machine-code fingerprints, address delta, function size, and branch-local boundaries before using it to tune S03.
   - Oracle-mapped code words may be used to repair the lab IDB when the user explicitly asks for oracle-assisted repair, but the repair artifact must be labeled `validation_only`.
   - Do not import oracle function names into production `functions.jsonl`, `call-graph.json`, comments, or final evidence. If temporary comments are useful for local readback, they must say that the oracle is validation-only.
   - Residual oracle-code mismatches after repeated apply/readback passes are S03 blockers until inspected as IDA item-head/tail conflicts, stale comments, function-boundary conflicts, or segment-coverage mismatches.
   - If the residual set is explicitly waived by the user or reviewer for forward progress, convert it to `accepted-risk` instead of deleting it. The downstream provenance must preserve the exact residual addresses, evidence artifacts, and the rule that any conclusion depending on those addresses remains `inferred` or `unresolved`.

9. Generalize the repair loop without requiring an oracle.
   - Production S03 uses the same loop shape: scan code-bearing ranges, propose boundary/code repairs, apply reviewed changes, export word/function state, compare readback against expected invariants, and iterate until blockers are zero or accepted-risk.
   - The oracle branch only replaces the expected-state source during lab tuning; it does not change the production exit contract.

10. Repair wrong tail-chunk ownership before code generation.
   - If a candidate entry is code but `get_func(candidate)` returns a function whose `start_ea` differs, inspect function chunks before treating it as unresolved.
   - If the candidate belongs to an unrelated owner as a tail chunk, propose `remove_func_tail(owner, candidate)` followed by an exact `add_func(candidate, end)` only when the chunk has a bounded control-flow role.
   - If a candidate is a shared suffix/local entry inside a larger function, split only when target-only evidence supports an independent entry: direct branch-to-entry, bounded suffix ending in return/tail branch, and architecture side effects that are coherent without the prefix.
   - After any repair, read back `get_func(candidate).start_ea == candidate` and Hex-Rays/disassembly availability before allowing S07 to mark it `codegen_ready`.
   - Do not lift Hex-Rays output for a containing function into source for the candidate address. A containing-function decompile is evidence for S03 repair, not evidence for S08 source.

## Outputs

Produce:

- `S03/functions.jsonl`
- `S03/call-graph.json`
- `S03/function-boundary-issues.jsonl`
- `S03/unowned-code-ranges.jsonl`
- `S03/records/recover-ida-functions.evidence.jsonl`
- `S03/records/recover-ida-functions.decisions.jsonl`
- `S03/records/recover-ida-functions.unknowns.jsonl`

Each function record should include:

- `address`
- `name`
- `size`
- `confidence`
- `branch_id` when part of the selected branch sample
- `boundary_status`
- `callers`
- `callees`
- `boundary_evidence`
- `open_questions`

## Boundaries

- Do not infer VM, scheduler, HKIP, Stage-2, or interrupt semantics.
- Do not rename IDA functions directly.
- Do not treat every branch target as a function.
- Do not hide unresolved function boundaries.
- Do not let a successful IDA writeback substitute for branch-level boundary validation.
- Do not read or depend on external symbol files during production recovery.

## Workflow v2 corpus-wide operation

For full source-repository recovery, do not use a fixed target address list. Run `scripts/export_full_ida_corpus.py` through IDA MCP to export all IDA functions, call graph edges, boundary issues, unowned code ranges, architecture events, and `S07/decompile-export-full.json`.

S03 corpus-wide exit requires every IDA function to appear in `S03/functions.jsonl`. Remaining unowned executable ranges or multi-chunk functions must be explicit in `function-boundary-issues.jsonl` or `unowned-code-ranges.jsonl`.
