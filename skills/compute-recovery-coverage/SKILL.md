---
name: compute-recovery-coverage
description: "Compute recovery coverage metrics for the hypervisor reverse-engineering workflow. Use in S09 to summarize function coverage, call graph coverage, type recovery, module attribution, C/asm/stub/unresolved ratios, and invariant evidence coverage."
---

# Compute Recovery Coverage

## Purpose

Compute coverage metrics for acceptance and delivery decisions.

## Inputs

Require:

- S03-S08 indexes
- `S08/coverage-summary.json`
- `S09/consistency-report.json`
- `S09/security-invariants.json`

## Workflow

1. Aggregate stage metrics.
2. Compute coverage by function, edge, type, module, source class, and invariant.
3. Separate production coverage from forward-test/oracle-only validation.
4. Emit machine-readable and report-ready summaries.

## Outputs

Produce:

- `S09/recovery-coverage.json`
- `S09/coverage-findings.jsonl`

## Boundaries

- Do not inflate metrics by counting unresolved or oracle-only evidence as recovered.
