---
name: recover-indirect-control-flow
description: "Recover indirect control-flow candidates from S03 function and data outputs. Use to identify jump tables, function-pointer tables, indirect calls, indirect branches, unresolved targets, and their evidence so downstream architecture and security stages can propagate uncertainty."
---

# Recover Indirect Control Flow

## Purpose

Make indirect control flow visible without inventing targets. This Skill consumes the function and data-object candidates from S03 workers and emits explicit resolved, partial, or unresolved target records.

This Skill may directly request read-only IDA/IDA MCP access for disassembly, xrefs, function boundaries, and data table inspection. Do not ask for a separate human confirmation for read-only connection; do not write IDA state.

## Inputs

Require:

- `S03/functions.jsonl`
- `S03/data-objects.jsonl`
- `S03/unresolved-regions.jsonl`
- `S02/ida-baseline-snapshot.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Locate indirect sites.
   - `BR`, `BLR`, `RET`-like patterns on ARM64.
   - Switch/jump-table patterns.
   - Loads through table-like data objects.

2. Build target candidates.
   - Use xrefs and data table entries when available.
   - Keep unresolved register-derived targets explicit.
   - Separate function pointers from data pointers.

3. Classify target quality.
   - `resolved`: all targets are enumerated and within known code ranges.
   - `partial`: some targets known, some unknown.
   - `unresolved`: target depends on runtime state or missing data.

## Outputs

Produce:

- `S03/indirect-targets.jsonl`
- `S03/records/recover-indirect-control-flow.evidence.jsonl`
- `S03/records/recover-indirect-control-flow.decisions.jsonl`
- `S03/records/recover-indirect-control-flow.unknowns.jsonl`

## Boundaries

- Do not resolve indirect calls by guessing from nearby names.
- Do not collapse unresolved control flow into direct edges.
- Do not modify IDA directly.
- Do not make security conclusions; only propagate uncertainty.
