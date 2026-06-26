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

## Workflow

1. Verify source-map completeness.
2. Compare function-level CFG/call/constant/memory-access summaries when available.
   - In review-seed mode, skip binary-equivalence comparisons for scaffold files without confirmed address mappings.
3. Check asm fallback ranges and stubs are explicit.
4. Emit mismatch findings with severity.

## Outputs

Produce:

- `S09/consistency-report.json`
- `S09/model-source-mismatches.jsonl`

## Boundaries

- Do not repair generated code.
- Do not rerun IDA analysis.
- Do not treat unresolved scaffold files as recovered code requiring CFG equivalence.
