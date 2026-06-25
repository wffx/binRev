---
name: resolve-arm64-load-address
description: "Evaluate ARM64 Image load base, entry, and segment candidates from a neutral IDA baseline. Use in S02 to score ADRP/ADD/LDR closure, branch target validity, pointer ranges, exception-vector alignment, and architecture anchors, while preserving multiple candidates or marking non-ARM64 samples as not applicable."
---

# Resolve ARM64 Load Address

## Purpose

Produce an evidence-backed address-space decision or candidate set. This Skill never fabricates a single confirmed base when evidence is insufficient.

This Skill may directly request read-only IDA/IDA MCP access when it needs current disassembly, xrefs, segments, functions, bytes, or metadata. Do not ask for a separate human confirmation for read-only connection; do not write IDA state.

## Inputs

Require:

- `S01/image-header.json`
- `S01/region-map.json`
- `S02/ida-baseline-snapshot.json`
- Neutral IDA baseline or opened IDA MCP session.

## Workflow

1. Check applicability.
   - Continue only when the sample is compatible with ARM64/AArch64 analysis.
   - If IDA reports another processor, emit `decision_status: not_applicable` with evidence.

2. Generate candidates.
   - Use Image header hints when compatible.
   - Use IDA entry and segment starts as candidates.
   - Keep raw-offset mode as a fallback candidate when virtual base is unresolved.

3. Score candidates.
   - ADRP/ADD/LDR reference closure.
   - Direct branch target validity.
   - Absolute pointer in-range ratio.
   - Exception vector alignment and reachable handlers.
   - EL2 system-register and event anchor consistency.
   - MMIO-looking address plausibility without overclaiming platform identity.

4. Emit decision.
   - Mark one base `confirmed` only when independent evidence classes agree.
   - Otherwise emit ranked candidates.
   - Put conflicts and missing evidence into unknown records.

## Outputs

Produce:

- `S02/address-space.json`
- `S02/records/resolve-arm64-load-address.evidence.jsonl`
- `S02/records/resolve-arm64-load-address.decisions.jsonl`
- `S02/records/resolve-arm64-load-address.unknowns.jsonl`

`address-space.json` should include:

- `decision_status`: `confirmed`, `candidate_set`, `raw_offset_only`, or `not_applicable`
- `entry_candidates`
- `base_candidates`
- `segment_candidates`
- `score_breakdown`
- `selected_base`
- `required_human_gate`

## Forward-test behavior

When used with `tests/xen.i64`, IDA reports `MetaPC` rather than ARM64. The correct result is `not_applicable`, while still proving that IDA metadata can be consumed.

## Boundaries

- Do not use Linux kernel layout assumptions as proof.
- Do not trust Hex-Rays output as the sole base evidence.
- Do not rename or modify IDA.
- Do not force ARM64 logic onto non-ARM64 test samples.
