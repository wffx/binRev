---
name: generate-final-recovery-report
description: "Generate the final hypervisor recovery report from S00-S09 artifacts. Use in S10 to summarize inputs, constraints, recovered architecture, repository layout, evidence coverage, unresolved risks, and audit results."
---

# Generate Final Recovery Report

## Purpose

Create the final human-readable recovery report.

If S09 is `review_seed_audit_ready_production_blocked`, generate a review-seed final report only. The report must state that production recovered-source delivery is blocked.

## Inputs

Require:

- S00-S09 stage manifests
- `S08/recovered-repo/`
- `S09/static-audit-report.md`
- coverage and unresolved indexes

## Workflow

1. Summarize input constraints and tool boundary.
2. Summarize recovered architecture and module layout.
3. Report coverage, confidence classes, unresolved items, and safety invariants.
   - In review-seed mode, report security invariants as unknown/not-evaluable and confirmed/inferred source coverage as zero.
4. Include exact artifact references and hashes.

## Outputs

Produce:

- `S10/final-recovery-report.md`
- `S10/final-recovery-report.json`

## Boundaries

- Do not change analysis results.
- Do not present forward-test artifacts as production evidence.
- Do not present review-seed delivery as production source recovery.
