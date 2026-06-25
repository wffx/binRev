---
name: integrate-hypervisor-runtime-model
description: "Integrate S05 CPU/vCPU and Stage-2 memory outputs into a unified hypervisor runtime object model. Use to reconcile CPU, vCPU, VM, context, VMID, page ownership, type candidates, blocking conflicts, and reviewed IDA proposals without applying them."
---

# Integrate Hypervisor Runtime Model

## Purpose

Merge S05 runtime workers into one ownership-safe runtime model for S06 service recovery. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S04/stage-manifest.json`
- `S04/architecture-model.json`
- `S05/cpu-vcpu-model.json`
- `S05/stage2-memory-model.json`
- `S05/records/recover-hypervisor-cpu-vcpu-model.*.jsonl`
- `S05/records/recover-hypervisor-stage2-memory-model.*.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Verify upstream readiness.
   - Require accepted S03 and S04.
   - If S03 or S04 is accepted with residual `accepted-risk`, preserve the accepted-risk artifact in S05 provenance. Do not block S05 solely for waived upstream residuals, but downgrade any runtime ownership conclusion that directly depends on a waived address to `review_only`, `inferred`, or `unresolved`.
   - Require CPU/vCPU and Stage-2 worker outputs to be internally valid.
   - If any upstream gate is blocked, emit `S05/runtime-object-model.json` only with `status: blocked_by_upstream`; do not mark S06 readiness.

2. Connect to IDA read-only when cross-checking current state.

3. Reconcile object references.
   - Link CPU, per-CPU, vCPU, context, VMID, Stage-2 root, and page ownership candidates.
   - Keep many-to-one and one-to-many ambiguities explicit.
   - Detect impossible ownership, such as one VMID bound to conflicting roots without migration evidence.
   - Treat seed-only models as `forward_test_review_required` until CPU/vCPU/context references and Stage-2 ownership are connected by dataflow or call graph evidence.
   - Treat function-level runtime clusters as stronger than raw sysreg hit lists, but still not final ownership. Clusters may support `review_only_links`; they do not become `ownership_links` until concrete dataflow or call graph ownership is recovered.
   - Keep `ICH_*` interrupt-interface clusters separate from Stage-2 root/VMID clusters. They may seed S06 interrupt/vCPU recovery but must not satisfy S05 Stage-2 ownership.

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
   - For repeatable root classification, use `scripts/classify_caller_root_matches.py` on the caller-argument propagation artifact before deciding S06 readiness.
   - Keep VTTBR field seeds and TPIDR indexed-variable seeds as `review_only_links`; do not upgrade them to `ownership_links` without a proven owner object and lifecycle path.
   - Keep shared caller clusters and TPIDR base-root classes as review-only until they are connected to a unique owner and resource lifetime.
   - Keep lifecycle edges as review-only if they only prove ordering, field writes, or state clears. Upgrade to ownership only when the same object is linked across allocation/init/start/stop/destroy or equivalent lifetime boundaries.
   - Treat teardown scans as negative/partial evidence when they find cleanup patterns without proving symmetry. Do not let high teardown scores override missing owner identity.
   - Treat exact owner/root closure as necessary but not always sufficient: still require VMID/resource identity or caller lifetime context before marking S06-ready ownership.
   - Do not promote same-helper or same-caller matches to `ownership_links` unless the common argument root is object-like and survives lifecycle-boundary checks.
   - Treat `object_like_count == 0` as a hard S06 production block. Service-local, global/constant, stack-local, and ambiguous roots may feed review queues only.
   - Set `s06_readiness.status` to a blocked state whenever ownership links are empty or only review-only.

5. Generate IDA proposal.
   - Propose only architecture/runtime-level comments or candidate names.
   - Do not propose VM config, scheduler, interrupt route, lifecycle, or HKIP names in S05.
   - Mark all high-risk names and type comments as review-only.
   - Do not use forward-test oracle databases, symbols, or source matches as production evidence. If an oracle is available during local skill development, keep it under validation artifacts and summarize only transferable heuristics in this Skill.

## Outputs

Produce:

- `S05/runtime-object-model.json`
- `S05/types.jsonl`
- `S05/resource-ownership.jsonl`
- `S05/ida-change-proposal.json`
- `S05/records/integrate-hypervisor-runtime-model.evidence.jsonl`
- `S05/records/integrate-hypervisor-runtime-model.decisions.jsonl`
- `S05/records/integrate-hypervisor-runtime-model.unknowns.jsonl`

`runtime-object-model.json` should include:

- `cpu_refs`
- `vcpu_refs`
- `context_refs`
- `vm_refs`
- `vmid_refs`
- `stage2_refs`
- `ownership_links`
- `blocking_unknowns`
- `s06_readiness`
- `upstream_gate`

## Boundaries

- Do not recover scheduler policy, VM configuration format, interrupt routing, lifecycle, or HKIP.
- Do not silently resolve ownership conflicts by choosing the most familiar open-source design.
- Do not apply IDA writes directly.
- Do not use external symbols, source code, logs, DTB, traces, or non-IDA reverse tools.
