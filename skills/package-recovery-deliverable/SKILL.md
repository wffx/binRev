---
name: package-recovery-deliverable
description: "Package the recovered hypervisor repository and recovery evidence for delivery. Use in S10 to freeze artifacts, manifests, source maps, reports, hashes, unresolved indexes, and reproduction instructions."
---

# Package Recovery Deliverable

## Purpose

Assemble the final deliverable bundle.

If S09 permits only review-seed delivery, package the unresolved scaffold, reports, indexes, hashes, and reproduction notes while marking production status as blocked.

## Inputs

Require:

- `S08/recovered-repo/`
- `S08/source-map.json`
- `S09/static-audit-report.md`
- `S10/final-recovery-report.md`
- all stage manifests and indexes

## Workflow

1. Verify required artifacts exist.
2. Generate hashes and package manifest.
3. Copy/freeze repository, reports, source maps, unresolved indexes, and audit artifacts.
4. Emit reproduction notes.
5. In review-seed mode, run `scripts/generate_s10_review_seed_package.py`.

## Outputs

Produce:

- `S10/deliverable/`
- `S10/package-manifest.json`
- `S10/artifact-hashes.json`

## Boundaries

- Do not rerun analysis.
- Do not omit unknowns, stubs, or unresolved indexes.
- Do not label the package as a production recovered-source release when S09 production is blocked.
