---
name: integrate-static-audit-report
description: "Integrate S09 consistency, security-invariant, and coverage findings into a static audit report. Use to produce review-ready findings, risks, accepted unknowns, and go/no-go recommendations without changing recovered code."
---

# Integrate Static Audit Report

## Purpose

Merge S09 audit workers into one review-ready static audit package.

## Inputs

Require:

- `S09/consistency-report.json`
- `S09/security-invariants.json`
- `S09/recovery-coverage.json`
- S03-S08 unknown indexes

## Workflow

1. Merge findings by severity and affected subsystem.
2. Deduplicate consistency/security/coverage findings.
3. Preserve accepted-risk and unknown items.
4. Emit final audit artifacts.

## Outputs

Produce:

- `S09/static-audit-report.md`
- `S09/static-audit-report.json`
- `S09/audit-findings.jsonl`

## Boundaries

- Do not modify source or IDA.
- Do not hide unresolved risks.
