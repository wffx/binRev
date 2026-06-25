---
name: recover-hypervisor-hkip-model
description: "Recover S07 HKIP or hypervisor-integrity-protection candidates from accepted runtime, memory, and service evidence. Use when the workflow needs protected regions, permission toggles, write windows, integrity metadata, verification paths, violation paths, and page/table protection evidence."
---

# Recover Hypervisor HKIP Model

## Purpose

Recover hypervisor integrity protection candidates without assuming the product-specific HKIP design. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S05/stage2-memory-model.json`
- `S05/resource-ownership.jsonl`
- `S06/service-model.json`
- `S04/architecture-events.jsonl`
- `S04/sysreg-accesses.jsonl`
- `S03/data-objects.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S06.
   - If page ownership or permission evidence is unstable, emit `blocked_by_upstream`.

2. Identify protection objects.
   - Track hypervisor text/rodata/page-table/metadata protection candidates.
   - Record permission-bit writes, temporary write windows, barriers/TLB invalidation, and violation paths.

3. Identify integrity mechanisms.
   - Track checksum/hash/table verification candidates only with dataflow evidence.
   - Do not classify a function as HKIP solely because it hashes memory.

4. Emit conservative model.
   - Separate protection, verification, update, and violation paths.
   - Keep ordinary page-permission logic distinct from HKIP candidates.

## Outputs

Produce:

- `S07/hkip-model.json`
- `S07/records/recover-hypervisor-hkip-model.evidence.jsonl`
- `S07/records/recover-hypervisor-hkip-model.decisions.jsonl`
- `S07/records/recover-hypervisor-hkip-model.unknowns.jsonl`

## Boundaries

- Do not claim vulnerability or bypass.
- Do not treat all read-only mappings as HKIP.
- Do not apply IDA writes directly.
