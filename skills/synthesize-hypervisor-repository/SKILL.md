---
name: synthesize-hypervisor-repository
description: "Synthesize the recovered hypervisor source repository skeleton from accepted S03-S07 models. Use in S08 to generate freestanding AArch64 C/assembly/module layout, asm fallback files, stubs, and build metadata without redoing reverse engineering or inventing unresolved logic."
---

# Synthesize Hypervisor Repository

## Purpose

Convert accepted recovery models into a readable, build-oriented repository skeleton. This Skill does not call IDA write operations and does not perform new reverse engineering.

If S07 is `review_seed_ready_production_blocked` and its S08 review-seed gate is ready, generate an unresolved/review-seed repository scaffold only. Do not synthesize confirmed C or assembly semantics from lifecycle/HKIP hypotheses.

## Inputs

Require accepted:

- `S03/program-model.json`
- `S04/architecture-model.json`
- `S05/runtime-object-model.json`
- `S06/service-model.json`
- `S07/security-lifecycle-model.json`
- stage evidence/decision/unknown indexes

Review-seed mode requires:

- `S07/stage-manifest.json`
- `S07/security-lifecycle-model.json`
- `S07/lifecycle-model.json`
- `S07/hkip-model.json`
- `S07/resource-transitions.jsonl`

## Workflow

1. Enforce model gates.
   - Use only accepted S03-S07 models.
   - If a required model is missing or forward-test only, generate an unresolved-only package or block S08.
   - If S07 allows only review-seed S08, run `scripts/generate_s08_review_seed_repository.py`.

2. Create repository layout.
   - Emit `arch/arm64`, `core`, `security/hkip`, `drivers`, `platform/unknown`, `include`, `recovered/asm_fallback`, `linker`, `tests`, and `.recovery`.

3. Synthesize source units.
   - Generate C only for confirmed or inferred-C functions with evidence.
   - Use `.S` fallback for world-switch, exception vectors, atomic fragments, and unresolved assembly-sensitive paths.
   - Use explicit failing stubs for external platform/hardware dependencies.
   - In review-seed mode, generate only explicit unresolved/failing stubs and traceable scaffold files.

4. Preserve traceability.
   - Every generated file/function/type must reference address ranges and evidence IDs.

## Outputs

Produce:

- `S08/recovered-repo/`
- `S08/recovery-index.json`
- `S08/build-manifest.json`
- `S08/unresolved-index.jsonl`

## Boundaries

- Do not invent business logic for unresolved functions.
- Do not aim for byte-identical Image reconstruction in S08.
- Do not write IDA.
- Do not convert `model_hypothesis` lifecycle, scheduler, interrupt, Stage-2, or HKIP records into source implementations.
