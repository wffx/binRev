# S09: Static Audit

## Goal

S09 audits the recovered repository and evidence indexes. In production mode it can evaluate consistency, coverage, and hypervisor security invariants. In review-seed mode it must limit itself to index consistency, honest coverage, and explicit unresolved blockers.

## Inputs

Production mode requires:

```text
S08/recovered-repo/
S08/source-map.json
S08/coverage-summary.json
S08/unresolved-index.jsonl
S05/resource-ownership.jsonl
S06/service-model.json
S07/security-lifecycle-model.json
S03-S08 evidence/decision/unknown indexes
```

Review-seed mode may consume:

```text
S08/stage-manifest.json
S08/recovery-index.json
S08/source-map.json
S08/coverage-summary.json
S08/recovery-evidence-index.json
S08/recovery-decision-index.json
S08/recovery-unknown-index.json
S08/unresolved-index.jsonl
```

## Skills

```text
check-recovered-code-consistency
check-hypervisor-security-invariants
compute-recovery-coverage
integrate-static-audit-report
```

## Production workflow

1. Check recovered code against binary-derived CFG, calls, constants, memory accesses, and source maps.
2. Evaluate VM page isolation, vCPU context separation, HKIP write protection, interrupt binding, and teardown cleanup invariants.
3. Compute function, call graph, type, module, source-class, and invariant coverage.
4. Integrate findings into a static audit report.

## Review-seed workflow

If S08 is `review_seed_repository_ready_production_blocked`:

1. Verify generated scaffold files have source-map entries.
2. Verify coverage does not claim confirmed or inferred-C source units.
3. Verify unresolved blockers are preserved.
4. Mark security invariants as `unknown` / `review_seed_not_evaluable`.
5. Emit a static audit report that recommends S10 review-seed packaging only.

## Outputs

```text
S09/
├── consistency-report.json
├── model-source-mismatches.jsonl
├── security-invariants.json
├── security-findings.jsonl
├── recovery-coverage.json
├── coverage-findings.jsonl
├── static-audit-report.json
├── static-audit-report.md
├── audit-findings.jsonl
├── stage-manifest.json
└── artifact-validation-rw1.json
```

## Exit conditions

Production exit requires:

- consistency findings are classified and linked to evidence;
- security invariants have evidence-backed `pass`, `fail`, `unknown`, or `not_applicable` verdicts;
- coverage is computed without Oracle contamination;
- unresolved risk is visible.

Review-seed exit requires:

- consistency checks pass for indexes/scaffold traceability;
- confirmed and inferred-C source coverage remain zero;
- security invariants do not receive production pass/fail verdicts;
- S10 readiness is limited to review-seed packaging.

## Boundaries

- Do not repair generated code.
- Do not rerun IDA analysis.
- Do not claim exploitability.
- Do not convert unknowns into passes.
- Do not present review-seed audits as production acceptance.
