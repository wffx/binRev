---
name: package-recovery-deliverable
description: "Package the recovered hypervisor repository and recovery evidence for delivery. Use in S09 to freeze artifacts, manifests, source maps, reports, hashes, unresolved indexes, and reproduction instructions."
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
- `S09/final-recovery-report.md`
- all stage manifests and indexes

Workflow v2 may instead require:

- canonical source repository under `recovered-repos/<case-id>/recovered-hypervisor/`
- `S08/source-repo-delivery.json`
- `S08/function-map.json`
- `S08/source-map.json`
- `S08/source-quality-report.json`
- `S09/source-repo-audit.json`
- `S09/static-audit-report.json`
- `S09/static-audit-report.md`

## Workflow

1. Verify required artifacts exist.
2. Generate hashes and package manifest.
3. Copy/freeze repository, reports, source maps, unresolved indexes, and audit artifacts.
   - In workflow v2, copy the canonical source repository to `S09/deliverable/source/recovered-hypervisor/`.
   - In workflow v2, copy JSON/JSONL evidence only to `S09/deliverable/evidence/`, never inside the source payload.
   - Include S06 type/offset/global review-seed evidence under `S09/deliverable/evidence/S06/` when present.
   - Include S08 presentation and planning evidence such as global aliases, offset-field annotations, externalized lifted pseudocode reviews, diagnostic-summary candidate indexes, candidate-driven names, simple-pseudocode names, module rehome indexes, source-symbol repair indexes, source-symbol repair normalization indexes, duplicate-wrong-file cleanup indexes, and source-class synchronization indexes under `S09/deliverable/evidence/S08/` when present.
4. Emit reproduction notes.
5. In review-seed mode, run `scripts/generate_s10_review_seed_package.py`.
6. In workflow v2, run `scripts/package_v2_source_delivery.py --case-id <case-id>`.
   - Preserve the upstream source status (`source_slice_ready`, `source_corpus_lifted`, `source_repo_semantic_partial`, or `source_repo_ready`). Do not promote a lifted corpus to source-repo-ready during packaging.
   - Preserve readability status exactly: full function coverage or full pseudocode evidence coverage is not enough to promote `source_corpus_lifted` when S09 still reports wrapper-body, source-symbol repair, semantic-ratio, generic-name, or IDA-residue blockers.
   - Emit a top-level `S09/deliverable/README.md` that explains source/evidence/report boundaries and repeats the S09 readability gates.

## Outputs

Produce:

- `S09/deliverable/`
- `S09/package-manifest.json`
- `S09/artifact-hashes.json`

Workflow v2 deliverable layout:

- `S09/deliverable/source/recovered-hypervisor/`
- `S09/deliverable/evidence/`
- `S09/deliverable/reports/`
- `S09/deliverable/README.md`

## Boundaries

- Do not rerun analysis.
- Do not omit unknowns, stubs, or unresolved indexes.
- Do not label the package as a production recovered-source release when S09 production is blocked.
- Do not place JSON/JSONL/IDA/SQLite artifacts inside `deliverable/source/recovered-hypervisor/`.
- Do not change the upstream source status while packaging.
