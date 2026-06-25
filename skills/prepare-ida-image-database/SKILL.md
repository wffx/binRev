---
name: prepare-ida-image-database
description: "Prepare a neutral IDA baseline for the single recovery binary or an existing IDB checkpoint. Use in S02 to open the input through IDA or IDA MCP, verify processor, endianness, file type, analysis status, initial entry and segments, and capture baseline metadata without adding business names or high-level types."
---

# Prepare IDA Image Database

## Purpose

Establish a neutral, reproducible IDA baseline. IDA MCP may be used as the transport to IDA, but the only analysis authority remains IDA state plus recorded artifacts.

## Inputs

Require:

- `S00/case-manifest.json`
- `S00/constraint-profile.json`
- `S01/image-header.json`
- `S01/region-map.json`
- `S01/embedded-candidates.json`
- The single input file, or an existing IDB checkpoint derived from that file.

## IDA access

Prefer native MCP tools when available:

- `open_idb`
- `analysis_status`
- `idb_meta`
- `list_functions`
- `disasm`
- `close_idb`

If the Codex session does not expose native `mcp__ida__...` tools, use the local `ida-mcp.exe` server or `probe` command as an IDA transport. Record the transport mode in output metadata.

IDA MCP connection and transport execution are normal Skill actions and do not require separate human confirmation. Any operation that creates, modifies, saves, or replaces an IDB still requires the S02 workflow route, proposal/decision record, and transaction trace.

## Workflow

1. Open the database or input.
   - Existing `.i64/.idb` files may be opened for validation.
   - Raw binaries may be opened only when the workflow explicitly asks to create a baseline.
   - Avoid rebuilding or auto-analyzing unless the Stage contract authorizes it.

2. Capture neutral metadata.
   - File type, processor, bitness, endianness, entry point, image base, segment list, function count, and analysis status.
   - Record whether analysis is complete, running, or incomplete.

3. Compare with S01.
   - Check whether IDA file type and processor agree with S01.
   - For incompatible samples, produce a neutral baseline with `target_compatibility: non_target_test_sample` or `incompatible`.

4. Avoid semantic pollution.
   - Do not rename functions.
   - Do not apply types.
   - Do not assert hypervisor modules.
   - Do not use decompiler output as source of truth for base selection.

## Outputs

Produce:

- `S02/ida-baseline.i64` or a reference to the opened checkpoint
- `S02/ida-baseline-snapshot.json`
- `S02/records/prepare-ida-image-database.evidence.jsonl`
- `S02/records/prepare-ida-image-database.decisions.jsonl`
- `S02/records/prepare-ida-image-database.unknowns.jsonl`

`ida-baseline-snapshot.json` should include:

- `ida_version`
- `transport`
- `opened_path`
- `file_type`
- `processor`
- `bits`
- `entry`
- `image_base`
- `segments`
- `function_count`
- `analysis_status`
- `target_compatibility`

## Boundaries

- Do not perform IDA writes beyond opening or saving an authorized neutral baseline.
- Do not infer business semantics.
- Do not accept IDA's automatic base as confirmed without S02 evidence.
- Do not use non-IDA reverse-engineering tools.
