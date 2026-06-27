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

## Workflow v2 source delivery

When using `workflow-source-recovery-v2.md`, S10 must package source and evidence separately:

```text
S10/deliverable/
├── source/
│   └── recovered-hypervisor/
├── evidence/
│   ├── S08/
│   └── S09/
└── reports/
```

The canonical source payload is:

```text
S10/deliverable/source/recovered-hypervisor/
```

It must contain `.c` and `.h` files and must not contain JSON, JSONL, SQLite, IDA database files, or other intermediate analysis artifacts. Evidence JSON/JSONL files may be packaged only under `S10/deliverable/evidence/`.

Additional v2 inputs:

```text
recovered-repos/<case-id>/recovered-hypervisor/
S08/source-repo-delivery.json
S08/function-map.json
S08/source-map.json
S08/source-quality-report.json
S09/source-repo-audit.json
S09/static-audit-report.json
S09/static-audit-report.md
```

Additional v2 outputs:

```text
S10/final-recovery-report.md
S10/final-recovery-report.json
S10/deliverable/source/recovered-hypervisor/
S10/deliverable/evidence/
S10/deliverable/reports/
S10/package-manifest.json
S10/artifact-hashes.json
S10/artifact-validation-rw1.json
```

V2 exit condition: the source payload is clean, hashes cover all packaged files, and the final report does not describe the evidence workspace as the source repository.

S10 must preserve the exact upstream status. In particular, a source payload with full function coverage and full pseudocode review-view coverage still remains `source_corpus_lifted` if S09 reports high wrapper-body or IDA-residue ratios.
