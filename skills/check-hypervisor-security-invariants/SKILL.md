---
name: check-hypervisor-security-invariants
description: "Check static security invariants over recovered hypervisor models. Use in S08 to evaluate VM isolation, vCPU context separation, HKIP write protection, interrupt route binding, and cleanup invariants from accepted S05-S07 artifacts."
---

# Check Hypervisor Security Invariants

## Purpose

Evaluate security invariants from accepted recovery models and generated trace maps.

If S08 is review-seed-only, emit invariant verdicts as `unknown` / `review_seed_not_evaluable`. Do not issue production `pass` or `fail` verdicts without confirmed source, resource ownership, lifecycle, and HKIP evidence.

## Inputs

Require:

- `S05/resource-ownership.jsonl`
- `S06/service-model.json`
- `S07/security-lifecycle-model.json`
- `S08/source-map.json`
- `S08/unresolved-index.jsonl`

## Workflow

1. Load invariant definitions.
2. Check VM page isolation, context separation, HKIP write protection, interrupt route binding, and teardown cleanup evidence.
3. Mark each invariant as `pass`, `fail`, `unknown`, or `not_applicable`.
   - In review-seed mode, mark security invariants as `unknown` unless production evidence exists.
4. Link every verdict to evidence or missing evidence.

## Outputs

Produce:

- `S08/security-invariants.json`
- `S08/security-findings.jsonl`

## Boundaries

- Do not claim exploitability.
- Do not convert unknowns into passes.
- Do not convert review-seed hypotheses into security invariant pass/fail verdicts.
