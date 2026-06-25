---
name: index-recovery-evidence
description: "Index recovered repository evidence and unresolved objects. Use in S08 to produce recovery coverage indexes, confidence summaries, unresolved/stubbed lists, and source-to-binary traceability for downstream audit and delivery."
---

# Index Recovery Evidence

## Purpose

Create the final S08 evidence and coverage indexes consumed by S09 audit and S10 packaging.

## Inputs

Require:

- `S08/source-map.json`
- `S08/recovery-index.json`
- `S08/unresolved-index.jsonl`
- S03-S07 stage indexes

## Workflow

1. Aggregate evidence and decision references.
2. Compute coverage metrics for functions, call graph, types, modules, C output, asm fallback, stubs, and unresolved objects.
3. Check that every source object has traceability.
4. Emit audit-ready indexes.

## Outputs

Produce:

- `S08/coverage-summary.json`
- `S08/recovery-evidence-index.json`
- `S08/recovery-decision-index.json`
- `S08/recovery-unknown-index.json`

## Boundaries

- Do not change source files.
- Do not suppress unknowns to improve metrics.
