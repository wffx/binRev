# ARM64 Hypervisor Source-Recovery Workflow v2

This file is the entry point for workflow v2.  Detailed contracts are split
under `specifications/workflows/source-recovery-v2/` so each part can evolve
without turning the workflow into a monolith.

## Purpose

Input one unsigned ARM64 hypervisor-like binary and produce a source repository
whose code is driven by IDA/assembly evidence, not by empty module stubs.

Oracle or symbolized binaries may be used only during lab validation. They are
not formal inputs and must not appear in production evidence chains.

## Stage sequence

```text
S00 Case initialization and constraint lock
S01 Binary/Image layout and load-address recovery
S02 IDA database preparation and capability handshake
S03 Code/data/function boundary recovery
S04 ARM64 EL2 architecture semantics
S05 Function clustering and module attribution
S06 Type, structure, global object, and argument propagation
S07 IDA decompile optimization loop
S08 Function-level source lifting and repository synthesis
S09 Semantic consistency, security-invariant, and coverage audit
S10 Final report and delivery package
```

## Split document map

| Document | Scope |
|---|---|
| [00-overview-and-policy.md](workflows/source-recovery-v2/00-overview-and-policy.md) | Purpose, formal inputs, Oracle boundary, core v2 policy. |
| [01-stages-s00-s03.md](workflows/source-recovery-v2/01-stages-s00-s03.md) | Case setup, Image layout, IDA handshake, boundary recovery. |
| [02-stages-s04-s07.md](workflows/source-recovery-v2/02-stages-s04-s07.md) | Architecture events, clustering, type propagation, IDA decompile loop. |
| [03-stage-s08-source-repository.md](workflows/source-recovery-v2/03-stage-s08-source-repository.md) | Source lifting, repository status, rewrite/naming/rehome/cleanup rules. |
| [04-stages-s09-s10-audit-delivery.md](workflows/source-recovery-v2/04-stages-s09-s10-audit-delivery.md) | Source audit, readability gates, S10 package layout and status rules. |
| [05-function-codegen-gate.md](workflows/source-recovery-v2/05-function-codegen-gate.md) | Function-level source generation gate and boundary mismatch rule. |

## Always-on invariants

1. Production input is one target binary plus IDA-derived evidence.
2. Oracle data is validation-only and must stay under validation/evaluation
   outputs, never production source evidence.
3. Every exported IDA function must be routed to exactly one output class:
   `semantic-c`, `lifted-c`, `asm-fallback`, or `unresolved`.
4. `lifted-c` and `semantic-c` are separate. Pseudocode evidence, comments, or
   wrapper bodies do not make a function semantic.
5. The canonical source repository is
   `recovered-repos/<case-id>/recovered-hypervisor/`.
6. `cases/<case-id>/stages/` is an evidence workspace, not the user-facing
   source repository.
7. Source repositories must contain source/build files such as `.c`, `.h`, and
   `.S`; JSON/JSONL/IDA/SQLite artifacts belong under evidence outputs only.
8. S10 must preserve the upstream source status. It must not promote
   `source_slice_ready` or `source_corpus_lifted` to `source_repo_ready`.

## Maintenance rule

When a stage rule changes, update the narrowest split document first. Only add
rules to this entry point if they are global invariants that affect multiple
stages.
