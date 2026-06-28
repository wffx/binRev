---
name: index-recovery-evidence
description: "Index recovered repository evidence and unresolved objects. Use in S07 to produce recovery coverage indexes, confidence summaries, unresolved/stubbed lists, and source-to-binary traceability for downstream audit and delivery."
---

# Index Recovery Evidence

## Purpose

Create the final S08 evidence and coverage indexes consumed by S09 audit and S10 packaging.

In review-seed S08, compute coverage honestly: confirmed and inferred-C coverage should remain zero if the repository contains only unresolved scaffold and explicit failing stubs.

## Inputs

Require:

- `S07/source-map.json`
- `S07/recovery-index.json`
- `S07/unresolved-index.jsonl`
- S03-S07 stage indexes

## Workflow

1. Aggregate evidence and decision references.
2. Compute coverage metrics for functions, call graph, types, modules, C output, asm fallback, stubs, and unresolved objects.
   - In review-seed mode, count unresolved/stubbed objects separately from confirmed or inferred-C recovery.
3. Check that every source object has traceability.
4. Emit audit-ready indexes.

## Outputs

Produce:

- `S07/coverage-summary.json`
- `S07/recovery-evidence-index.json`
- `S07/recovery-decision-index.json`
- `S07/recovery-unknown-index.json`

## Boundaries

- Do not change source files.
- Do not suppress unknowns to improve metrics.
- Do not treat review-seed scaffold files as recovered functional code.
