---
name: check-hypervisor-security-invariants
description: "Check static security invariants over recovered hypervisor models. Use in S09 to evaluate VM isolation, vCPU context separation, HKIP write protection, interrupt route binding, and cleanup invariants from accepted S05-S08 artifacts."
---

# Check Hypervisor Security Invariants

## Purpose

Evaluate security invariants from accepted recovery models and generated trace maps.

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
4. Link every verdict to evidence or missing evidence.

## Outputs

Produce:

- `S09/security-invariants.json`
- `S09/security-findings.jsonl`

## Boundaries

- Do not claim exploitability.
- Do not convert unknowns into passes.
