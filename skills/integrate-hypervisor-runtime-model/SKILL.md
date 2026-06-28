---
name: integrate-hypervisor-runtime-model
description: "Integrate S04 CPU/vCPU and Stage-2 memory outputs into a unified hypervisor runtime object model. Use to reconcile CPU, vCPU, VM, context, VMID, page ownership, type candidates, blocking conflicts, and reviewed IDA proposals without applying them."
---

# Integrate Hypervisor Runtime Model

## Purpose

Merge S04 runtime workers into one ownership-safe runtime model for S05 service recovery. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S02/stage-manifest.json`
- `S03/stage-manifest.json`
- `S03/architecture-model.json`
- `S04/cpu-vcpu-model.json`
- `S04/stage2-memory-model.json`
- `S04/records/recover-hypervisor-cpu-vcpu-model.*.jsonl`
- `S04/records/recover-hypervisor-stage2-memory-model.*.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Verify upstream readiness.
   - Require accepted S02 and S03.
   - If S02 or S03 is accepted with residual `accepted-risk`, preserve the accepted-risk artifact in S04 provenance. Do not block S04 solely for waived upstream residuals, but downgrade any runtime ownership conclusion that directly depends on a waived address to `review_only`, `inferred`, or `unresolved`.
   - Require CPU/vCPU and Stage-2 worker outputs to be internally valid.
   - If any upstream gate is blocked, emit `S04/runtime-object-model.json` only with `status: blocked_by_upstream`; do not mark S05 readiness.

2. Connect to IDA read-only when cross-checking current state.

3. Reconcile object references.
   - Link CPU, per-CPU, vCPU, context, VMID, Stage-2 root, and page ownership candidates.
   - Keep many-to-one and one-to-many ambiguities explicit.
   - Detect impossible ownership, such as one VMID bound to conflicting roots without migration evidence.
   - Treat seed-only models as `forward_test_review_required` until CPU/vCPU/context references and Stage-2 ownership are connected by dataflow or call graph evidence.
   - Treat function-level runtime clusters as stronger than raw sysreg hit lists, but still not final ownership. Clusters may support `review_only_links`; they do not become `ownership_links` until concrete dataflow or call graph ownership is recovered.
   - Keep `ICH_*` interrupt-interface clusters separate from Stage-2 root/VMID clusters. They may seed S05 interrupt/vCPU recovery but must not satisfy S04 Stage-2 ownership.

4. Build type and ownership candidates.
   - Emit offset-first type candidates, not final source structs.
   - Record owner, lifetime hints, field offsets, access widths, and evidence IDs.
   - Convert unresolved conflicts into blocking Unknowns.
   - If only sysreg/event anchors exist, emit type seeds and blocking Unknowns rather than final `runtime-object-model` ownership links.
   - Use `review_required_runtime_anchor_clusters` when clusters are coherent but CPU/vCPU/VM/Stage-2 ownership remains unproven.
   - Use `review_required_dataflow_slices` when local dataflow yields field seeds, such as VTTBR source offsets or TPIDR-indexed variable tables, but owner/lifetime links remain unresolved.
   - Use `review_required_owner_base_traces` when caller/base traces identify likely lifetime clusters or per-CPU table roots but still lack allocation/init/start/teardown proof.
   - Use `review_required_lifecycle_edges` when lifecycle-like prepare/activate/setup/reset/flag-clear edges are visible but still lack a unique owner, VMID relationship, or teardown proof.
   - Use `review_required_teardown_scan` when teardown-like or rollback-like candidates exist but are not argument/root matched to the setup/activation owner.
   - Use `review_required_owner_root_match` when owner/root matching has been attempted but produces only weak matches, such as same offset or same lifecycle field family without a shared root signature.
   - Use `review_required_caller_argument_propagation` when caller argument roots match but remain service-local, global/constant-rooted, stack-rooted, or otherwise not tied to VM/Stage-2 lifecycle ownership.
   - Use `review_required_root_classification` when caller-root classification has no object-like roots or only ambiguous roots.
   - For repeatable root classification, use `scripts/classify_caller_root_matches.py` on the caller-argument propagation artifact before deciding S05 readiness.
   - If root classification produces no object-like roots, run `scripts/plan_owner_root_continuation.py` to split review-only matches into helper self-loop, global-state, per-CPU-state, stack-parent-trace, and ambiguous-backtrace queues. Use `review_required_root_continuation_plan` for that state.
   - After continuation planning, run `scripts/expand_owner_root_anchors.py` with RW2/RW3/RW6/RW9 artifacts to expand per-CPU, global, and stack anchors against existing dataflow/owner-root evidence. Use `review_required_anchor_expansion` when the expansion identifies trace families but still lacks owner lifetime/resource identity closure.
   - If IDA read-only access is available, run `scripts/ida_s05_rw11_anchor_xref_trace.py` to trace dominant global xrefs/writes and TPIDR offset-family read/write uses. Treat its output as evidence only; do not promote ownership until lifecycle/resource identity is proven.
   - After RW11, run `scripts/ida_s05_rw12_writer_lifetime_closure.py` to inspect the unique global writer, nearby init/lifetime call window, and direct closure to TPIDR-heavy candidates. Use `review_required_writer_lifetime_closure` when a writer exists but value-source/resource identity remains unresolved.
   - After RW12, run `scripts/ida_s05_rw13_global_value_source_trace.py` to trace global store value sources and reader consumer patterns. When ARM64 return values are forwarded through `MOV Wn, W0` or `MOV Xn, X0` into a store, keep scanning backward past the forwarding instruction to the nearest producer call or definition. Use `review_required_global_value_source_trace` when the global is count/config-like or scalar-like and still not an object owner.
   - After count/config-like globals are excluded, run `scripts/ida_s05_rw14_tpidr_offset_family_trace.py` to follow short local windows after `MRS <reg>, TPIDR_EL2` and recover TPIDR-indexed slot/field families. Treat only `[Xn,#imm]` base+immediate forms as field offsets; do not treat shift scales such as `LSL#3` as offsets. Match registers with token boundaries so hexadecimal immediates such as `0x108` do not create false `X1` dependencies. Use `review_required_tpidr_offset_family_trace` until field families are connected to lifecycle/resource identity.
   - After RW14, run `scripts/ida_s05_rw15_tpidr_writer_lifecycle_trace.py` to scan full-IDB same-offset writers/clearers and separate them from function-local TPIDR-confirmed field writes. Treat same-offset hits as broad candidates only. Treat TPIDR-confirmed writer/clearer functions as lifecycle candidates, not ownership links, until the same owner is connected across init/start/stop/destroy and VM/vCPU/Stage-2 resource identity. Use `review_required_tpidr_writer_lifecycle_trace`.
   - After RW15, run `scripts/ida_s05_rw16_lifecycle_bridge_trace.py` to bridge writer/clearer seed functions through callers, callees, nearby call windows, strings, sysregs, and RW4 lifecycle summaries. Count clear evidence only for store-zero or explicit zero-value definitions; do not treat arbitrary `XZR/WZR` use in arithmetic as a lifecycle clear. Use `review_required_lifecycle_bridge_trace` until a bridge proves same-owner resource identity.
   - After RW16, run `scripts/ida_s05_rw17_cross_function_arg_bridge.py` to compare argument roots across shared caller/callee bridge pairs. Preserve symbols/text for address-materializing `ADD/ADRP/ADRL` roots; never collapse unrelated static addresses or logging strings into the same generic compute root. Treat shared static/per-CPU roots as review-only context, not ownership. Use `review_required_cross_function_arg_bridge`.
   - After RW17, run `scripts/finalize_s05_convergence_gate.py` to summarize RW8-RW17 and decide whether S04 has production ownership links. If ownership links remain empty and the best bridges are static/per-CPU context rather than VM/vCPU/Stage-2 resource identity, set `not_accepted_review_required_converged_no_object_owner_root` and keep S05 blocked for production. Do not continue blind S04 expansion or fabricate ownership links.
   - Keep VTTBR field seeds and TPIDR indexed-variable seeds as `review_only_links`; do not upgrade them to `ownership_links` without a proven owner object and lifecycle path.
   - Keep shared caller clusters and TPIDR base-root classes as review-only until they are connected to a unique owner and resource lifetime.
   - Keep lifecycle edges as review-only if they only prove ordering, field writes, or state clears. Upgrade to ownership only when the same object is linked across allocation/init/start/stop/destroy or equivalent lifetime boundaries.
   - Treat teardown scans as negative/partial evidence when they find cleanup patterns without proving symmetry. Do not let high teardown scores override missing owner identity.
   - Treat exact owner/root closure as necessary but not always sufficient: still require VMID/resource identity or caller lifetime context before marking S05-ready ownership.
   - Do not promote same-helper or same-caller matches to `ownership_links` unless the common argument root is object-like and survives lifecycle-boundary checks.
   - Treat `object_like_count == 0` as a hard S05 production block. Service-local, global/constant, stack-local, and ambiguous roots may feed review queues only.
   - Set `s05_readiness.status` to a blocked state whenever ownership links are empty or only review-only.

5. Generate IDA proposal.
   - Propose only architecture/runtime-level comments or candidate names.
   - Do not propose VM config, scheduler, interrupt route, lifecycle, or HKIP names in S04.
   - Mark all high-risk names and type comments as review-only.
   - Do not use forward-test oracle databases, symbols, or source matches as production evidence. If an oracle is available during local skill development, keep it under validation artifacts and summarize only transferable heuristics in this Skill.

## Outputs

Produce:

- `S04/runtime-object-model.json`
- `S04/types.jsonl`
- `S04/resource-ownership.jsonl`
- `S04/ida-change-proposal.json`
- `S04/records/integrate-hypervisor-runtime-model.evidence.jsonl`
- `S04/records/integrate-hypervisor-runtime-model.decisions.jsonl`
- `S04/records/integrate-hypervisor-runtime-model.unknowns.jsonl`

`runtime-object-model.json` should include:

- `cpu_refs`
- `vcpu_refs`
- `context_refs`
- `vm_refs`
- `vmid_refs`
- `stage2_refs`
- `ownership_links`
- `blocking_unknowns`
- `s05_readiness`
- `upstream_gate`

## Boundaries

- Do not recover scheduler policy, VM configuration format, interrupt routing, lifecycle, or HKIP.
- Do not silently resolve ownership conflicts by choosing the most familiar open-source design.
- Do not apply IDA writes directly.
- Do not use external symbols, source code, logs, DTB, traces, or non-IDA reverse tools.

## S04 function clustering

This Skill performs function clustering and module attribution.

Produce these primary artifacts:

- `S04/function-clusters.json`
- `S04/module-attribution.json`
- `S04/cluster-readiness.json`

Cluster functions by:

- S02 boundaries and call graph;
- S03 architecture events;
- sysreg/MMIO access families;
- TPIDR_EL2/VTTBR_EL2/VTCR_EL2/TLBI/ICH/CNT/GIC anchors;
- xrefs, globals, strings, and data-object neighborhoods.

Do not require final VM/vCPU/Stage-2 ownership before S05. S04 v2 readiness means a cluster is ready for type/object/argument propagation, not that the business object model is proven.

In corpus-wide mode, S04 must cluster every S02 function and produce `S04/directory-plan.json`. Low-confidence functions must be routed to `recovered/unknown/cluster_xx` rather than omitted. Report total function count, clustered function count, and unknown-cluster count.

## S05 offset/global type seeds

Run `scripts/recover_offset_global_families.py --case-id <case-id> --emit-header` after S07/S08 corpus exports exist.

This S05 pass must:

- mine Hex-Rays pseudocode for repeated argument-base offsets such as `a1 + 0x18`;
- record access width, hit count, function count, source file, module, and examples;
- mine high-frequency `qword_*`, `dword_*`, `byte_*` globals and classify them as review-only global state candidates;
- emit `S05/struct-layouts.jsonl`, `S05/global-object-model.json`, `S05/argument-flow.jsonl`, `S05/type-candidates.json`, and `S05/offset-global-recovery-summary.json`;
- optionally emit `include/recovered/recovered_objects.h` into the canonical source repo as a review-seed header.

Do not treat candidate structs as confirmed source layouts. If offsets overlap or ownership is unknown, generated headers must preserve field offsets in comments and use raw storage rather than pretending the exact C struct is known. Do not apply IDA type writes from this pass without a reviewed S07 transaction.
