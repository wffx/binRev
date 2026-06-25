---
name: classify-binary-regions
description: "Classify file-offset regions in the single recovery binary after S01 Image layout analysis. Use to produce a complete, non-overlapping region map for header, code candidate, read-only data candidate, writable data candidate, appended data, embedded candidates, and unknown ranges while preserving uncertainty."
---

# Classify Binary Regions

## Purpose

Produce a complete file-offset region map without pretending to know more than the bytes support. This Skill prepares safe input for IDA loading and later code/data separation.

## Inputs

Require:

- `S00/case-manifest.json`
- `S00/constraint-profile.json`
- `S01/image-header.json`
- `S01/embedded-candidates.json`
- The single input file.

Do not read IDA state.

## Workflow

1. Start from known ranges.
   - Include Image header, declared payload, appended range, and embedded candidate ranges from S01.
   - If S01 marked the format incompatible, classify the file as `unknown_target_format` with optional generic byte-feature ranges.

2. Detect byte-feature ranges.
   - Record zero-fill, repeated fill, high entropy, ASCII/UTF-16 strings, aligned pointer-looking values, and dense instruction-looking ranges.
   - Treat these as evidence hints, not final semantics.

3. Build a non-overlapping map.
   - Every byte must belong to exactly one region.
   - Split regions when evidence changes.
   - Prefer `unknown` over forced code/data classification.

4. Preserve confidence.
   - Use confidence levels: `confirmed`, `candidate`, `unknown`.
   - Record reason codes, file offsets, and source evidence IDs.

## Outputs

Produce:

- `S01/region-map.json`
- `S01/string-index.jsonl`
- `S01/records/classify-binary-regions.evidence.jsonl`
- `S01/records/classify-binary-regions.decisions.jsonl`
- `S01/records/classify-binary-regions.unknowns.jsonl`

`region-map.json` should include:

- `coverage`: full file byte coverage
- `regions`: offset, size, class, confidence, evidence IDs
- `overlap_check`
- `gap_check`
- `format_dependency`

## Boundaries

- Do not invoke IDA or IDA MCP.
- Do not create function boundaries.
- Do not assign virtual addresses or segment permissions.
- Do not call high entropy encrypted, compressed, or signed unless structural evidence supports that label.
