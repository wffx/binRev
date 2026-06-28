---
name: recover-hypervisor-hkip-model
description: "Recover S06 HKIP or hypervisor-integrity-protection candidates from accepted runtime, memory, and service evidence. Use when the workflow needs protected regions, permission toggles, write windows, integrity metadata, verification paths, violation paths, and page/table protection evidence."
---

# Recover Hypervisor HKIP Model

## Purpose

Recover hypervisor integrity protection candidates without assuming the product-specific HKIP design. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

If upstream evidence is review-seed-only, emit `absent_or_unknown` HKIP outputs unless protected regions, permission toggles, write windows, integrity metadata, or violation paths are proven by binary/IDA evidence.

## Inputs

Require:

- `S04/stage2-memory-model.json`
- `S04/resource-ownership.jsonl`
- `S05/service-model.json`
- `S05/ida-stage.i64`
- `S03/architecture-events.jsonl`
- `S03/sysreg-accesses.jsonl`
- `S03/data-objects.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03-S05.
   - If S04/S05 are review-seed-only, keep HKIP in review-seed mode and block production HKIP confirmation.
   - If page ownership or permission evidence is unstable, emit `blocked_by_upstream`.

2. Identify protection objects.
   - Track hypervisor text/rodata/page-table/metadata protection candidates.
   - Record permission-bit writes, temporary write windows, barriers/TLB invalidation, and violation paths.
   - **String xref enumeration（字符串交叉引用全量枚举）**: 对本阶段相关的每个证据字符串（`XSM Framework`, `Flask: boundary violated`, `Flask: permission`, `Permission fault`, `xsm_set_system_active` 等），执行 `ida_xrefs_to_string` 获取所有 xref 地址，**必须遍历全部 xref**，找唯一包含函数并去重。赋予安全域前缀命名（`candidate_security_*`, `candidate_hkip_*`）。
   - **Call graph propagation**: 对每个已命名的 HKIP 锚点函数，遍历直接 callees，赋予安全域命名。传播深度 1 层。

3. Identify integrity mechanisms.
   - Track checksum/hash/table verification candidates only with dataflow evidence.
   - Do not classify a function as HKIP solely because it hashes memory.

4. Emit conservative model.
   - Separate protection, verification, update, and violation paths.
   - Keep ordinary page-permission logic distinct from HKIP candidates.
   - If no HKIP-specific object is proven, emit explicit negative/unknown records rather than an empty successful model.

## Outputs

Produce:

- `S06/hkip-model.json`
- `S06/records/recover-hypervisor-hkip-model.evidence.jsonl`
- `S06/records/recover-hypervisor-hkip-model.decisions.jsonl`
- `S06/records/recover-hypervisor-hkip-model.unknowns.jsonl`

## Boundaries

- Do not claim vulnerability or bypass.
- Do not treat all read-only mappings as HKIP.
- Do not classify generic Stage-2/page-table permission code as HKIP without protected-object and permission-transition evidence.
- Do not apply IDA writes directly.
