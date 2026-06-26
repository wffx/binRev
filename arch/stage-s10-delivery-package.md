# S10: Final Report and Delivery Package

## Goal

S10 freezes the recovery outputs into a delivery package. If production recovery is blocked, S10 must deliver a review-seed package that preserves evidence, unresolved indexes, audit reports, hashes, and reproduction notes without presenting the result as recovered production source.

## Inputs

Production mode requires:

```text
S08/recovered-repo/
S08/source-map.json
S09/static-audit-report.md
S10/final-recovery-report.md
all stage manifests and indexes
```

Review-seed mode may consume:

```text
S08/recovered-repo/
S08/source-map.json
S08/unresolved-index.jsonl
S09/static-audit-report.md
S09/stage-manifest.json
```

## Skills

```text
generate-final-recovery-report
package-recovery-deliverable
```

## Production workflow

1. Verify all required artifacts exist.
2. Generate final human-readable and machine-readable reports.
3. Freeze recovered repository, source maps, audit reports, unresolved indexes, and manifests.
4. Generate hashes and package manifest.
5. Emit reproduction notes.

## Review-seed workflow

If S09 is `review_seed_audit_ready_production_blocked`:

1. Generate a final report that states production recovery is blocked.
2. Package the unresolved scaffold, reports, indexes, and manifests.
3. Include unresolved indexes and unknown/security audit blockers.
4. Generate hashes for every packaged file.
5. Mark the review-seed package as complete while keeping production blocked.

## Outputs

```text
S10/
├── final-recovery-report.md
├── final-recovery-report.json
├── deliverable/
├── package-manifest.json
├── artifact-hashes.json
├── stage-manifest.json
└── artifact-validation-rw1.json
```

## Exit conditions

Production exit requires:

- final report and package manifest exist;
- source, maps, indexes, audit reports, unknowns, and hashes are included;
- package status matches the actual audit gate.

Review-seed exit requires:

- production status is explicitly blocked;
- review-seed deliverable is complete;
- unresolved indexes are included;
- hashes cover every packaged file.

## Boundaries

- Do not rerun analysis.
- Do not omit unknowns, stubs, or unresolved indexes.
- Do not present review-seed delivery as production source recovery.
