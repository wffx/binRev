---
name: integrate-static-audit-report
description: "Integrate S08 consistency, security-invariant, and coverage findings into a static audit report. Use to produce review-ready findings, risks, accepted unknowns, and go/no-go recommendations without changing recovered code."
---

# Integrate Static Audit Report

## Purpose

Merge S08 audit workers into one review-ready static audit package.

If S08 is review-seed-only, integrate a review-seed audit package: consistency and coverage may pass, but security invariants must remain unknown/not-evaluable and production delivery must remain blocked.

## Inputs

Require:

- `S08/consistency-report.json`
- `S08/security-invariants.json`
- `S08/recovery-coverage.json`
- S03-S08 unknown indexes

## Workflow

1. Merge findings by severity and affected subsystem.
2. Deduplicate consistency/security/coverage findings.
3. Preserve accepted-risk and unknown items.
4. Emit final audit artifacts.
5. In review-seed mode, run `scripts/generate_s09_review_seed_audit.py`.

## Outputs

Produce:

- `S08/static-audit-report.md`
- `S08/static-audit-report.json`
- `S08/audit-findings.jsonl`

## Boundaries

- Do not modify source or IDA.
- Do not hide unresolved risks.
- Do not present review-seed audits as production acceptance.
