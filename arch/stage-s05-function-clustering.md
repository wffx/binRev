# S05: Function Clustering and Module Attribution

S05 groups functions into evidence-backed clusters. It no longer tries to finalize VM/vCPU/Stage-2 ownership by itself.

## Goal

Identify coherent function groups that can be recovered together.

## Inputs

- S03 function/data/control-flow boundaries.
- S04 architecture events and sysreg/MMIO anchors.
- IDA call graph, xrefs, strings, and globals.

## Outputs

- `function-clusters.json`
- `module-attribution.json`
- `cluster-readiness.json`
- cluster evidence/decision/unknown records.

## Exit condition

At least one cluster is ready for S06 type/object propagation, or every cluster has explicit blockers.

## Boundary

Do not generate source code. Do not claim business semantics from names alone.

## Corpus-wide rule

S05 is not complete when only a representative branch or hand-picked module is clustered. It must cluster every S03 function and produce `directory-plan.json`.

Each function must have exactly one primary module attribution. Low-confidence functions are routed to `recovered/unknown/cluster_xx` rather than being dropped.

Required corpus metrics:

- total S03 function count;
- clustered function count;
- functions per cluster;
- directory path for every cluster;
- low-confidence unknown cluster count.
