# S08: Repository Synthesis

## Goal

S08 converts accepted recovery models into a traceable source repository. When upstream recovery is blocked and only review seeds exist, S08 must generate an unresolved scaffold and indexes, not pretend to have recovered implementation logic.

## Inputs

Production mode requires accepted S03-S07 models:

```text
S03/program-model.json
S04/architecture-model.json
S05/runtime-object-model.json
S06/service-model.json
S07/security-lifecycle-model.json
stage evidence/decision/unknown indexes
```

Review-seed mode may consume:

```text
S07/stage-manifest.json
S07/security-lifecycle-model.json
S07/lifecycle-model.json
S07/hkip-model.json
S07/resource-transitions.jsonl
```

## Skills

```text
synthesize-hypervisor-repository
generate-recovery-source-map
index-recovery-evidence
```

## Production workflow

1. Enforce accepted S03-S07 gates.
2. Create the repository layout.
3. Generate source units only for confirmed or inferred-C functions.
4. Preserve assembly-sensitive regions as `.S` fallback.
5. Emit explicit failing stubs for external platform or hardware dependencies.
6. Build source maps and evidence indexes.

## Review-seed workflow

If S07 allows only unresolved/review-seed repository scaffolding:

1. Create the target repository layout.
2. Generate only unresolved scaffold files, explicit failing stubs, and metadata.
3. Leave confirmed and inferred-C source-unit lists empty.
4. Leave address-to-source function mappings empty unless already proven upstream.
5. Emit unresolved indexes that explain why production source synthesis is blocked.
6. Allow S09 only to perform index-consistency audit, not final security-invariant verdicts.

## Outputs

```text
S08/
├── recovered-repo/
├── recovery-index.json
├── build-manifest.json
├── source-map.json
├── address-to-source.json
├── evidence-to-source.json
├── coverage-summary.json
├── recovery-evidence-index.json
├── recovery-decision-index.json
├── recovery-unknown-index.json
├── unresolved-index.jsonl
├── stage-manifest.json
└── artifact-validation-rw1.json
```

## Exit conditions

Production exit requires:

- generated source units trace back to confirmed/inferred evidence;
- every generated function/type/file has source-map coverage;
- unresolved and stubbed items are explicit;
- no model hypothesis is promoted into implementation.

Review-seed exit requires:

- repository scaffold exists;
- confirmed and inferred-C source units remain zero;
- unresolved blockers are indexed;
- S09 readiness is limited to index consistency.

## Boundaries

- Do not invent business logic for unresolved functions.
- Do not aim for byte-identical Image reconstruction in S08.
- Do not write IDA.
- Do not treat review-seed scaffold files as recovered functional code.
