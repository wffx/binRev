---
name: initialize-hypervisor-recovery-case
description: "Initialize a single-binary reverse-engineering recovery case for the ARM64 EL2 Hypervisor Image workflow. Use in S00 to freeze exactly one input file, calculate its SHA-256, create the case identity, record user-provided format and business background, and separate binary facts from assumptions."
---

# Initialize Hypervisor Recovery Case

## Purpose

Create the immutable case identity used by every later artifact. This Skill records facts about the one input file; it does not analyze implementation semantics, invoke IDA, create functions, or infer architecture behavior.

## Inputs

Require:

- One input file path, normally `input/Image`.
- `case-request.json` containing only declared format, byte order, and business background.
- Workspace output root for Stage artifacts.

Reject multiple binaries unless the caller explicitly starts a new separate case.

## Workflow

1. Verify input uniqueness.
   - Confirm the input is exactly one regular file.
   - Record path, file name, size, timestamps if available, and SHA-256.
   - Do not treat sidecar files, IDBs, logs, source trees, or comments as sample evidence.

2. Create case identity.
   - Derive a stable `case_id` from project name, file basename, SHA-256 prefix, and creation time.
   - Keep the full SHA-256 as the authoritative sample identity.

3. Separate fact classes.
   - Binary facts: path, size, hash, byte-order claim, declared format.
   - User background: hypervisor, CPU/vCPU, VM, Stage-2, scheduler, lifecycle, HKIP, interrupt passthrough.
   - Unknowns: anything not proven by the single binary at S00.

4. Emit records.
   - Write evidence for file existence, size, hash, and request fields.
   - Write unknowns for unverified architecture, platform, boot mode, symbols, provenance, and runtime behavior.

## Outputs

Produce:

- `S00/case-manifest.json`
- `S00/records/initialize-hypervisor-recovery-case.evidence.jsonl`
- `S00/records/initialize-hypervisor-recovery-case.decisions.jsonl`
- `S00/records/initialize-hypervisor-recovery-case.unknowns.jsonl`

`case-manifest.json` should include:

- `case_id`
- `image_path`
- `image_sha256`
- `image_size`
- `declared_format`
- `declared_endianness`
- `business_background`
- `created_at`
- `producer`

## Boundaries

- Do not inspect code, strings, or headers beyond what is needed to identify the file.
- Do not invoke IDA or IDA MCP.
- Do not claim the binary is truly ARM64, EL2, Linux Image, Xen, or hypervisor code at S00.
- Do not merge external source knowledge into case facts.
