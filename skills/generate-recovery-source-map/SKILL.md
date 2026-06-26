---
name: generate-recovery-source-map
description: "Generate source mapping for recovered hypervisor repository artifacts. Use in S08 to map each generated file, function, type, field, asm fallback, stub, and unresolved item back to Image addresses, IDA objects, evidence IDs, and decision IDs."
---

# Generate Recovery Source Map

## Purpose

Build a machine-readable trace map from generated repository objects back to binary evidence.

In review-seed S08, source-map generation must preserve the fact that repository files are unresolved scaffold objects. It must not create address-to-function mappings when no confirmed source unit exists.

## Inputs

Require:

- `S08/recovered-repo/`
- `S08/recovery-index.json`
- S03-S07 evidence/decision/unknown indexes
- accepted stage manifests

## Workflow

1. Index generated files and symbols.
2. Link every object to address ranges and evidence IDs.
3. Mark confidence class: `confirmed`, `inferred-c`, `asm-fallback`, `stubbed`, or `unresolved`.
   - In review-seed mode, prefer `unresolved` or `asm-fallback`; leave address ranges empty unless a previous stage provides confirmed mapping evidence.
4. Emit reverse lookup maps by address, source path, function, and evidence.

## Outputs

Produce:

- `S08/source-map.json`
- `S08/address-to-source.json`
- `S08/evidence-to-source.json`

## Boundaries

- Do not synthesize new code.
- Do not modify accepted models.
- Do not hide unresolved or stubbed objects.
- Do not manufacture source mappings for review-seed hypotheses.
