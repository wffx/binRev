---
name: check-recovered-code-consistency
description: "Check static consistency of recovered hypervisor code and models. Use in S09 to compare generated CFG/calls/constants/memory accesses with accepted binary evidence, validate source maps, and flag mismatches without repairing code."
---

# Check Recovered Code Consistency

## Purpose

Validate that generated source artifacts remain consistent with accepted recovery evidence.

If S08 is `review_seed_repository_ready_production_blocked`, run only index/source-map consistency checks. Do not compare CFG/calls/constants for unresolved scaffold files.

## Inputs

Require:

- `S08/recovered-repo/`
- `S08/source-map.json`
- `S08/coverage-summary.json`
- accepted S03-S07 models

Workflow v2 may instead require:

- `S08/source-repo-delivery.json`
- `S08/function-map.json`
- `S08/source-map.json`
- `S08/source-quality-report.json`
- `S08/unresolved-index.jsonl`
- canonical source repository under `recovered-repos/<case-id>/recovered-hypervisor/`

## Workflow

1. Verify source-map completeness.
   - In workflow v2, verify every function-map entry has a source-map entry and that each mapped symbol is present in the canonical source repository.
   - In workflow v2, verify every primary source symbol has exactly one canonical definition across `.c` files.
2. Compare function-level CFG/call/constant/memory-access summaries when available.
   - In review-seed mode, skip binary-equivalence comparisons for scaffold files without confirmed address mappings.
3. Check asm fallback ranges and stubs are explicit.
   - In workflow v2, reject fake internal stubs and reject `codegen_ready` functions that have no source implementation.
4. Emit mismatch findings with severity.
5. In workflow v2, run `scripts/audit_v2_source_repo.py --case-id <case-id>` to audit canonical source-repo purity.
6. In corpus-wide mode, require coverage metrics: IDA function count, clustered function count, generated source function count, output-class counts, unresolved count, and source purity.
7. In corpus-wide mode, run `scripts/audit_corpus_readability.py --case-id <case-id>` and block `source_repo_ready` if semantic ratio, wrapper ratio, source-symbol repair wrapper ratio, pseudocode evidence coverage, or IDA residue thresholds fail. Count inline pseudocode and `S08/lifted-pseudocode-review.jsonl` externalized evidence separately, then report the total evidence ratio.
8. After readability audit, run `scripts/plan_semantic_rewrite.py --case-id <case-id>` to rank the next S08 semantic rewrite batches. Treat `semantic-c` labels with generic wrapper bodies as readability debt.
9. Treat generic source-symbol ratio as a source-readability blocker. `source_repo_ready` requires generic helper/access names to be reduced by S06/S08 semantic naming, not merely hidden in evidence.
10. Treat IDA/address-style primary source symbols (`sub_*`, `nullsub_*`) as a separate blocker from comment/pseudocode residue. They may remain in evidence comments and source maps, but not as primary source function names in a ready repository.
11. Count broad architecture placeholder names such as `runtime_access_current_cpu_state_N`, `percpu_access_current_cpu_state_N`, `boot_access_current_cpu_state_N`, and repeated `arm64_cache_tlb_maintenance_N` as generic source symbols. These names are better than raw addresses but are still not source-repo-ready semantic names.
12. Check address, output-class, and confidence consistency across `function-map.json`, `source-map.json`, source evidence comments, and rewrite indexes. A source evidence comment must identify the same image offset as the mapped function, not merely the same class/confidence. A diagnostic summary rewrite must have a source body marker and a `semantic-c` function-map class.
13. Count `source-symbol repair` wrappers separately from normal lifted wrappers. They are acceptable as an emergency coverage repair after source-file corruption or rehome drift, but they are a `source_repo_ready` blocker until replaced by normal lifted/semantic bodies from S08.
14. Fail on duplicate primary source-symbol definitions. A symbol found in two `.c` files means source organization drift; S08 must remove or rehome the noncanonical copy before S10 packaging.

## Outputs

Produce:

- `S09/source-repo-audit.json`
- `S09/readability-report.json`
- `S09/readability-report.md`
- `S09/semantic-rewrite-plan.json`
- `S09/semantic-rewrite-plan.md`
- `S09/consistency-report.json`
- `S09/model-source-mismatches.jsonl`

## Boundaries

- Do not repair generated code.
- Do not rerun IDA analysis.
- Do not treat unresolved scaffold files as recovered code requiring CFG equivalence.
- Do not call `cases/<case-id>/stages` the source repository. It is an evidence workspace; the canonical source repository is under `recovered-repos/<case-id>/recovered-hypervisor/`.
- Do not accept a report that only says `pass` without corpus coverage counts.
- Do not promote wrapper-body or comment-only lifted code to semantic source.
- Do not conflate non-compiling Hex-Rays pseudocode review blocks, whether inline or externalized, with recovered executable C bodies.
- Do not trust `semantic-c` labels alone; check whether the generated body is still a generic recovered wrapper.
- Do not accept a source repository whose primary symbols are still dominated by generated helper/access names or IDA/address-style names.
- Do not allow map/source drift: if the map says `semantic-c` but source comments or rewrite evidence still say `lifted-c`, or if evidence confidence is stale, fail S09 consistency.
- Do not hide source-symbol repair wrappers inside the normal wrapper ratio. They must remain visible as a separate coverage-repair debt.
- Do not allow duplicate recovered function definitions. Coverage is not valid unless each function-map symbol reads back to one canonical source definition.
