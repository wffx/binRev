---
name: analyze-arm64-image-layout
description: "Analyze the file-level layout of a little-endian ARM64 boot executable Image. Use in S01 to parse the Image header when present, record declared size and flags, identify appended bytes and embedded-object candidates, and explicitly mark non-target or ambiguous formats without inferring business semantics or virtual load addresses."
---

# Analyze ARM64 Image Layout

## Purpose

Recover only file-format facts from the input binary. This Skill is conservative: it may conclude that the input is not an ARM64 boot executable Image, or that layout is ambiguous.

## Inputs

Require:

- `S00/case-manifest.json`
- `S00/constraint-profile.json`
- The single input file recorded in the case manifest.

Do not read IDA state.

## Workflow

1. Read the file header.
   - For an ARM64 boot executable Image, parse the documented header fields and byte order.
   - Verify magic, text offset, image size, flags, and reserved fields when present.
   - If magic or structure is incompatible, emit `format_status: incompatible` rather than forcing interpretation.

2. Compare declared and observed size.
   - Record full file size.
   - Record declared payload size when available.
   - Mark appended bytes as candidate appended data only when the boundary is evidence-backed.

3. Identify embedded candidates.
   - Scan for candidate DTB, compression headers, configuration blobs, signatures, and high-entropy ranges.
   - Mark all such objects as `candidate` unless their internal structure validates.

4. Produce file-offset evidence.
   - Use file offsets, lengths, byte samples, and structural checks.
   - Do not assign virtual addresses.
   - Do not infer functions, modules, or hypervisor behavior.

## Outputs

Produce:

- `S01/image-header.json`
- `S01/embedded-candidates.json`
- `S01/records/analyze-arm64-image-layout.evidence.jsonl`
- `S01/records/analyze-arm64-image-layout.decisions.jsonl`
- `S01/records/analyze-arm64-image-layout.unknowns.jsonl`

`image-header.json` should include:

- `format_status`: `compatible`, `incompatible`, or `ambiguous`
- `endianness`
- `file_size`
- parsed header fields when compatible
- `declared_payload_range`
- `appended_range`
- validation notes

## Forward-test behavior

When run against a non-target sample such as an x86 ELF/Xen IDB companion binary, this Skill should clearly emit `format_status: incompatible` and preserve that as a boundary finding. That is a success case for the Skill, not a failure.

## Boundaries

- Do not invoke IDA or IDA MCP.
- Do not infer load base, entry point, or segment permissions.
- Do not treat strings or entropy as business facts.
- Do not repair or synthesize an Image header.
