---
name: recover-hypervisor-cpu-vcpu-model
description: "Recover S05 CPU/vCPU runtime object candidates from accepted S03 and S04 ARM64 EL2 evidence. Use when the workflow needs MPIDR/per-CPU/vCPU/context-reference relationships, CPU on/off paths, world-switch anchors, and ownership-safe runtime object evidence without assigning VM service policy."
---

# Recover Hypervisor CPU/vCPU Model

## Purpose

Recover CPU, per-CPU, vCPU, and context-reference candidates from target Image and IDA evidence. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/call-graph.json`
- `S03/indirect-targets.jsonl`
- `S03/unresolved-regions*.jsonl`
- `S04/stage-manifest.json`
- `S04/architecture-model.json`
- `S04/context-layouts.jsonl`
- `S04/sysreg-accesses.jsonl`
- `S04/architecture-events.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03 and accepted S04 for production recovery.
   - If either upstream stage is `rework_required`, `blocked`, or `forward_test_deferred_by_s03_rework`, emit only a blocked/forward-test note; do not produce S05-ready runtime objects.
   - Treat S03 blocking unresolved blobs and S04 blocking unknowns as hard exclusions for object ownership.

2. Connect to IDA read-only and record transport metadata.

3. Identify CPU and per-CPU anchors.
   - Track `MPIDR_EL1`, `TPIDR_EL2`, affinity extraction, CPU-release polling, CPU parking loops, and CPU-local stack/base references.
   - Record base registers, strides, array-like access patterns, and initialization order before naming objects.
   - Aggregate dense `TPIDR_EL2` hits by containing function, base register, and data target before emitting candidates. Do not flatten thousands of `TPIDR_EL2` sites into separate per-CPU objects.
   - Prefer a runtime-cluster artifact over raw hit lists: group `TPIDR_EL2` by function, nearby memory uses of the destination register, callers/callees, and string/diagnostic density.
   - Prioritize `MPIDR_EL1` sites for physical CPU affinity and boot/secondary CPU identification; use `TPIDR_EL2` primarily as per-CPU/current-context seed until ownership is confirmed.
   - Treat very dense `TPIDR_EL2` functions as accessors or current-context hubs until dataflow proves a concrete owner. High hit count alone is not enough to create a final CPU or vCPU object.
   - For each `MRS Xt, TPIDR_EL2`, run a local forward slice for uses of `Xt`. Distinguish direct-base uses (`[Xt,#off]`) from indexed-variable uses (`[Xbase,Xt]`).
   - Treat `[Xbase, Xtpidr]` as a per-CPU indexed variable-table seed. It is not evidence that `TPIDR_EL2` is a vCPU or current-context struct pointer.
   - If top `TPIDR_EL2` clusters only show indexed-variable access, emit blocking Unknowns for per-CPU base-table identity and vCPU ownership.
   - For each indexed-variable use, backward-slice `Xbase` and classify its root as `address_literal`, `memory_load`, `stack_reload`, `sysreg`, or unresolved.
   - Treat `address_literal` roots as global per-CPU table seeds and `memory_load`/`stack_reload` roots as runtime table/object-load seeds. Both remain review-only until connected to CPU lifecycle or vCPU context.
   - Do not upgrade TPIDR base-root classes to ownership links unless the table identity and owner lifetime are both recovered.

4. Identify vCPU/context anchors.
   - Use S04 offset-first context records and save/restore paths.
   - Track world-switch-like paths, `ELR_EL2`/`SPSR_EL2` transfer, GPR/sysreg save/restore, and persistent context base references.
   - Do not assume a context object is a vCPU unless cross-references and ownership evidence support it.
   - If `ICH_*` system-register clusters such as `ICH_HCR_EL2` appear, record them as vCPU interrupt-interface hints and route them to S06 interrupt recovery. Do not merge them into Stage-2 or CPU ownership.

5. Build ownership-safe candidates.
   - Emit candidate object IDs with evidence IDs, address ranges, base references, offsets, and confidence.
   - Mark ambiguous CPU/vCPU/VM ownership as Unknown, not as final type.
   - A seed model may be useful with only CPU/per-CPU/context anchors, but S06 readiness requires integrated ownership, not just sysreg hit counts.
   - If only MPIDR/TPIDR/context-save anchors exist, set `model_status: review_required_runtime_anchor_clusters` or equivalent and emit blocking Unknowns for per-CPU/vCPU ownership.

## Outputs

Produce:

- `S05/cpu-vcpu-model.json`
- `S05/records/recover-hypervisor-cpu-vcpu-model.evidence.jsonl`
- `S05/records/recover-hypervisor-cpu-vcpu-model.decisions.jsonl`
- `S05/records/recover-hypervisor-cpu-vcpu-model.unknowns.jsonl`

`cpu-vcpu-model.json` should include:

- `cpu_candidates`
- `percpu_candidates`
- `vcpu_candidates`
- `context_refs`
- `world_switch_anchors`
- `cpu_lifecycle_anchors`
- `ownership_unknowns`
- `upstream_gate`

## Boundaries

- Do not recover VM configuration, scheduler policy, interrupt routing, lifecycle, or HKIP.
- Do not assign final C struct names or field names; keep offset-first runtime candidates.
- Do not use external symbols, source code, logs, DTB, traces, or non-IDA reverse tools.
- Do not apply IDA writes directly.
