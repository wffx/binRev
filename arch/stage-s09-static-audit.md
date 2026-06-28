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

## Source repository audit

S09 must distinguish the canonical source repository from the evidence workspace:

```text
canonical source repository:
  recovered-repos/<case-id>/recovered-hypervisor/

evidence workspace:
  cases/<case-id>/stages/
```

Additional v2 inputs:

```text
S08/source-repo-delivery.json
S08/function-map.json
S08/source-map.json
S08/source-quality-report.json
S08/unresolved-index.jsonl
recovered-repos/<case-id>/recovered-hypervisor/
```

Additional v2 checks:

1. The canonical source repository contains `.c` and `.h` files.
2. The canonical source repository does not contain JSON, JSONL, SQLite, IDA, or other intermediate analysis artifacts.
3. Every `S08/function-map.json` function has a `S08/source-map.json` source entry.
4. Every mapped source symbol reads back from the canonical source repository.
5. Every primary source symbol has exactly one canonical `.c` definition. Duplicate definitions across files fail S09 even if source-map readback succeeds.
6. `fake_stub_files` is zero unless a future workflow explicitly permits external platform stubs.
7. `codegen_ready_without_source` is zero before S10 packaging can claim source delivery readiness.
8. Readability metrics are computed: semantic-c ratio, lifted-c ratio, wrapper-body ratio, source-symbol repair wrapper ratio, and IDA residue score.
9. Pseudocode review-view coverage is computed separately. A high pseudocode-view ratio improves auditability but does not pass semantic-readiness gates by itself.
10. Semantic-label/body mismatch is computed. A function labeled `semantic-c` but implemented only as a generic wrapper remains readability debt until the executable body is rewritten.
11. Primary source symbols are audited separately from comments/pseudocode. Generic helper names and IDA/address names such as `runtime_helper_0001`, `interrupt_helper_0001`, `timer_control_0001`, `sub_1234`, or `nullsub_7` block `source_repo_ready` even when function coverage is complete.
12. Address, output-class, and confidence consistency are checked across `function-map.json`, `source-map.json`, source evidence comments, and rewrite indexes. A source evidence comment must name the same image offset as the mapped function, not only a compatible class/confidence. A diagnostic-summary rewrite must have a matching source body marker and `semantic-c` map class.
13. Source-symbol repair wrappers are audited separately. They may be used to restore full function coverage after a source organization/regeneration bug, but they keep the package at `source_corpus_lifted` until S08 replaces them with normal lifted/semantic source bodies.

Additional v2 outputs:

```text
S09/source-repo-audit.json
S09/readability-report.json
S09/readability-report.md
S09/semantic-rewrite-plan.json
S09/semantic-rewrite-plan.md
S09/consistency-report.json
S09/model-source-mismatches.jsonl
S09/static-audit-report.json
S09/static-audit-report.md
S09/audit-findings.jsonl
```

V2 exit condition: canonical source-repo purity passes, source-map symbols read back from `.c`/`.h` files, readability gates report whether the corpus is merely lifted or semantically ready, source-symbol repair wrappers are visible as coverage-repair debt, pseudocode-view coverage is visible but not conflated with semantic source, semantic-label/body mismatch is visible, primary source-symbol residue is measured, and any remaining unmapped or unresolved item is explicit in S09 findings.

S09 must fail consistency if maps and source disagree about a function's output class or evidence confidence. This prevents a rewrite batch from promoting `function-map.json` while leaving stale `class lifted-c` / `confidence medium` comments or missing diagnostic-summary body markers in user-facing source.
