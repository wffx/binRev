---
name: recover-hypervisor-stage2-memory-model
description: "Recover S04 Stage-2 memory isolation candidates from accepted S02 and S03 ARM64 EL2 evidence. Use when the workflow needs VTCR/VTTBR/VMID/page-table descriptor/map-unmap/fault/ownership evidence without importing Linux, KVM, Xen, or Hafnium implementation details."
---

# Recover Hypervisor Stage-2 Memory Model

## Purpose

Recover Stage-2 translation, VMID, page-table, and memory-ownership candidates from target instructions and IDA evidence. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S02/stage-manifest.json`
- `S02/program-model.json`
- `S02/functions.jsonl`
- `S02/data-objects.jsonl`
- `S02/data-islands.jsonl`
- `S02/call-graph.json`
- `S02/unresolved-regions*.jsonl`
- `S03/stage-manifest.json`
- `S03/architecture-model.json`
- `S03/sysreg-accesses.jsonl`
- `S03/architecture-events.jsonl`
- `S03/ida-stage.i64`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S02 and accepted S03 for production recovery.
   - If upstream is not accepted, emit blocked/forward-test status and do not produce S05-consumable ownership.
   - Exclude S02 blocking unresolved blob ranges from page-table root or descriptor claims.

2. Connect to IDA read-only and record transport metadata.

3. Identify Stage-2 architecture anchors.
   - Track `VTCR_EL2`, `VTTBR_EL2`, `VMID`, `HPFAR_EL2`, `FAR_EL2`, `ESR_EL2`, and Stage-2 fault-related paths.
   - Link `TLBI`, `DSB`, `ISB`, cache maintenance, and TTBR/VTTBR writes to nearby memory updates.
   - Prioritize function clusters containing `VTCR_EL2` and `VTTBR_EL2` writes as Stage-2 root/VMID anchors.
   - Match true `HCR_EL2` separately from interrupt-controller registers such as `ICH_HCR_EL2`. Route `ICH_*` clusters to interrupt/vCPU-interface recovery; do not count them as Stage-2 memory anchors.
   - Prefer function-level clusters over raw sysreg hits. Rank clusters by `VTTBR_EL2`/`VTCR_EL2` reads and writes, nearby `TLBI`, barrier instructions, caller/callee context, and diagnostic density.
   - Treat `HPFAR_EL2`, `FAR_EL2`, and `ESR_EL2` clusters as fault-path anchors; do not confuse diagnostic print functions with ownership-changing handlers.
   - Reject or downgrade diagnostic-heavy functions before claiming a fault handler. Indicators include multiple format-string references, register dump strings, and sysreg reads immediately followed by print-like calls.
   - Use `TLBI` as supporting evidence only when linked to VTTBR/descriptor/page-table writes or map/unmap-like memory updates.

4. Recover descriptor and table evidence.
   - Detect descriptor-width stores, bit masks, address alignment, table walks, and allocation/free-like references.
   - Emit descriptor bit observations; do not force final Arm descriptor interpretation without local evidence.
   - For each `MSR VTTBR_EL2, Xt`, perform a local backward register slice for `Xt`. Record memory source fields, shifts, masks, and constants.
   - Treat `LSL #12` before `MSR VTTBR_EL2` as a strong field-layout seed for a page-number/root-base representation, not as final descriptor ownership.
   - If a function only reads `VTTBR_EL2` and never writes it, downgrade it to observer/diagnostic unless caller dataflow proves it controls a switch.
   - Preserve field seeds such as object offset `0x28` or nested chains such as `0x18 -> 0x228` as review-only offsets until the owning VM/vCPU/runtime object is recovered.
   - Do not claim VMID recovery unless the slice exposes VMID-like masks, shifts, or source fields. A VTTBR base/root write alone is insufficient.

5. Recover memory ownership candidates.
   - Track map/unmap/protect/share/reclaim-like state transitions only when call graph and data writes support them.
   - Distinguish hypervisor-private, VM-owned, shared, device, and unknown pages as candidates.
   - Preserve conflicting or cross-VM ownership as blocking Unknown.
   - Do not mark S05-ready ownership from Stage-2 sysreg anchors alone; descriptor layout and page/resource ownership must be integrated first.
   - If VTTBR/VTCR/TLBI clusters are present but descriptor stores and owner transitions are not recovered, emit Stage-2 root/VMID seeds plus a blocking Unknown; do not produce final ownership links.
   - Trace callers of VTTBR field-seed functions. Promote shared caller clusters only to review-only lifetime/service candidates until allocation/init/start/teardown edges prove ownership.
   - Treat a common caller feeding multiple VTTBR paths, such as one caller invoking both a field update path and a VTTBR write path, as a lifetime-cluster seed rather than a final VM owner.
   - Record caller argument roots and local field offsets. Stable offsets across switch/restore paths may become type seeds, but still need owner and lifecycle proof before S05 production.
   - When a caller writes preparation fields and then calls VTTBR activation paths, classify it as a review-only lifecycle edge. Do not claim the owner until the object is tied to allocation/init/start/teardown and VM/vCPU identity.
   - Treat stable switch fields such as setup fields, VTTBR source fields, and state/flag clears as lifecycle field seeds. Keep them offset-first and review-only.
   - If lifecycle edges strengthen confidence but VMID, owner object, or teardown path is still missing, keep S04 in review-required state and block S05 production.
   - Search teardown, rollback, free, destroy, remove, and unmap-like paths by watching lifecycle offsets and Stage-2/TLBI side effects. Treat this as candidate discovery only.
   - For repeatable IDA headless owner/root matching, use `scripts/owner_root_match_ida.py` with `CASE_ID`, `SETUP_FUNCS`, `TEARDOWN_SCAN`, `WATCH_OFFSETS`, and `OUT_NAME` environment variables.
   - Do not accept teardown from keyword strings, zero stores, barriers, or TLBI alone. Require argument/root matching that ties teardown to the same object used by prepare/activate/setup paths.
   - Classify owner/root matches by evidence strength. Exact root-signature or caller argument propagation may become strong review evidence; same offset, same field family, or same cleanup idiom alone is only a weak review hint.
   - When caller argument propagation finds common roots, classify the root before promotion. Object-like roots may support ownership review; global constants, address literals, stack reloads, same-helper callsites, and service-local switch helpers do not prove VM/Stage-2 lifecycle ownership by themselves.
   - If no object-like root remains after classification, emit a blocking Unknown for Stage-2 ownership closure and leave S05 blocked.
   - If setup and teardown paths share offsets such as `0x18`, `0x20`, `0x28`, or `0x41` but have no common root signature, do not infer a symmetric lifecycle object.
   - If teardown-like candidates are not connected to the same owner object, emit partial cleanup evidence and keep S05 blocked.

## Outputs

Produce:

- `S04/stage2-memory-model.json`
- `S04/records/recover-hypervisor-stage2-memory-model.evidence.jsonl`
- `S04/records/recover-hypervisor-stage2-memory-model.decisions.jsonl`
- `S04/records/recover-hypervisor-stage2-memory-model.unknowns.jsonl`

`stage2-memory-model.json` should include:

- `stage2_root_candidates`
- `vmid_candidates`
- `descriptor_observations`
- `map_unmap_candidates`
- `fault_path_candidates`
- `ownership_candidates`
- `tlbi_barrier_links`
- `blocking_unknowns`
- `upstream_gate`

## Boundaries

- Do not recover VM lifecycle or service configuration.
- Do not claim HKIP solely from page permission changes; HKIP belongs to S07.
- Do not import page-table helpers or constants from open-source projects as target evidence.
- Do not apply IDA writes directly.
