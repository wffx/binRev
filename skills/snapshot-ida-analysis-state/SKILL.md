---
name: snapshot-ida-analysis-state
description: "Snapshot accepted IDA analysis state for S02-S07 of the ARM64 EL2 Hypervisor Image recovery workflow. Use after reviewed IDA changes or baseline preparation to export a versioned IDB reference and normalized JSON metadata for processor, segments, functions, xrefs, types, comments, analysis status, and source artifact identity."
---

# Snapshot IDA Analysis State

## Purpose

Create a reproducible IDA checkpoint and normalized metadata snapshot for downstream Stages. This Skill records state; it does not propose new analysis conclusions.

IDA MCP connection for metadata export or checkpoint operations does not require separate human confirmation. Saving or copying a checkpoint is allowed when the current Stage route and transaction discipline authorize it.

## Inputs

Require:

- Current Stage ID from S02 through S07.
- Accepted IDA database or IDA MCP session.
- Current Case ID and input SHA-256.
- Accepted IDA transaction log when changes were applied.

## Workflow

1. Verify checkpoint source.
   - Confirm the IDA state derives from the single case input.
   - Confirm Stage is allowed to snapshot IDA.
   - Confirm no unreviewed changes are waiting to be applied.

2. Capture IDB identity.
   - Record database path, file type, processor, bitness, endianness, image base, and analysis status.
   - Record IDA version and transport mode.

3. Capture normalized metadata.
   - Segments: name, start, end, permissions, class.
   - Functions: address, name, size, flags, confidence when available.
   - Xref summary when available.
   - Types, comments, enums, structs, and source mappings when available.

4. Save or reference checkpoint.
   - If saving is authorized, write the versioned `.i64/.idb` checkpoint.
   - If operating read-only, record the existing checkpoint path and hash instead.

## Outputs

Produce:

- `Sxx/ida-stage.i64` or the Stage-specific baseline path required by the workflow.
- `Sxx/ida-stage-snapshot.json` or `S02/ida-baseline-snapshot.json`.
- `Sxx/records/snapshot-ida-analysis-state.evidence.jsonl`
- `Sxx/records/snapshot-ida-analysis-state.decisions.jsonl`
- `Sxx/records/snapshot-ida-analysis-state.unknowns.jsonl`

Snapshot JSON should include:

- `stage_id`
- `case_id`
- `image_sha256`
- `idb_path`
- `idb_hash`
- `ida_version`
- `transport`
- `file_type`
- `processor`
- `bits`
- `image_base`
- `analysis_status`
- `segments`
- `functions_summary`
- `xrefs_summary`
- `transaction_refs`

## Boundaries

- Do not infer semantics from the snapshot.
- Do not rename, type, patch, or comment.
- Do not hide analysis warnings.
- Do not create checkpoints for S00, S01, S08, S09, or S10 unless explicitly required by delivery packaging.
