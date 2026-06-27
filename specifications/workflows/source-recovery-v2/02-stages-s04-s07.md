# Stages S04-S07: Architecture, Clustering, Types, and IDA Feedback

## S04: ARM64 EL2 architecture semantics

Goal: identify architecture-level behavior independent of product names.

Required work:

- boot flow;
- exception vectors;
- context save/restore;
- sysreg accesses;
- MMU/TLB/cache maintenance;
- GIC/timer/SMMU/SMCCC/PSCI anchors.

Outputs:

- architecture model;
- sysreg events;
- architecture event index;
- context layout seeds.

Exit condition: architecture anchors can seed function clustering and type
propagation.

## S05: Function clustering and module attribution

Goal: group all exported functions into recoverable clusters before claiming
source modules.

Cluster examples:

- boot/MMU;
- exception/vector;
- per-CPU/TPIDR;
- timer/IRQ;
- Stage-2 memory;
- scheduler/world-switch;
- VM config/lifecycle;
- HKIP/security protection.

Inputs:

- S03 boundaries;
- S04 architecture events;
- IDA call graph/xrefs;
- strings and globals;
- sysreg/MMIO access clusters.

Outputs:

- `function-clusters.json`;
- `module-attribution.json`;
- `cluster-readiness.json`;
- cluster unknowns.

Exit condition: every S03 function has a cluster and directory attribution.
Low-confidence functions must be routed to `recovered/unknown/cluster_xx`, not
dropped.

## S06: Type, structure, global object, and argument propagation

Goal: improve decompiler quality by recovering data shapes.

Required work:

- infer structure offset families;
- identify global object roots;
- propagate argument roots across callsites;
- separate scalar/count/config globals from owner objects;
- propose structs/enums/function prototypes for IDA;
- recover corpus-wide offset-family and global-object review seeds from
  Hex-Rays pseudocode;
- emit candidate source headers only when they preserve uncertainty and do not
  pretend to be confirmed layouts.

Outputs:

- `type-candidates.json`;
- `struct-layouts.jsonl`;
- `global-object-model.json`;
- `argument-flow.jsonl`;
- IDA type/name/comment proposal;
- offset/global recovery summary;
- optional review-seed recovered object header.

Exit condition: cluster functions have typed context, offset/global review
seeds, or explicit fallback reasons. Candidate structs and globals are not
ownership proof and do not by themselves justify `source_repo_ready`.

## S07: IDA decompile optimization loop

Goal: apply reviewed high-confidence analysis improvements and re-export
decompiler evidence.

Workflow:

1. Export current decompile/disassembly evidence.
2. Generate proposals for names, comments, prototypes, structs, enums, arrays,
   and data items.
3. Apply only reviewed or high-confidence safe changes.
4. Re-decompile affected functions.
5. Compare quality before/after.

Outputs:

- IDA change proposals;
- IDA change transactions;
- decompile-quality report;
- codegen-ready function list.

Exit condition: functions are classified as `codegen_ready`, `asm_fallback`, or
`unresolved`.
