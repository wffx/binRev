# Skill Forward Test: Round 2 Workflow v2

This note records the Round 2 forward-test used to validate the adjusted source-recovery workflow and related Skills.

## Scope

- Target binary: `tests/Round 2/xen_arm64`
- Target IDB: `tests/Round 2/xen_arm64.i64`
- Validation-only Oracle: `tests/Round 2/xen_arm64_syms`
- Case id: `round2-xen_arm64-778090a1`
- Target SHA-256: `778090a16c51b1e6445643aa88c6564d938fcdb46138c387c87dbec1ec42569f`
- Oracle SHA-256: `e863bbb8886e6af7b3f1a1a382d257cd4ce4cd16642cfcf891a2679e1c00e61f`

The Oracle is not a formal input. It is used only to score workflow quality during lab development.

## Artifacts

- IDA export: `cases/round2-xen_arm64-778090a1/stages/S07/ida-decompile-export-rw1.json`
- S05 clusters: `cases/round2-xen_arm64-778090a1/stages/S05/function-clusters.json`
- S06 type seeds: `cases/round2-xen_arm64-778090a1/stages/S06/type-candidates.json`
- S07 codegen gate: `cases/round2-xen_arm64-778090a1/stages/S07/codegen-ready-functions.jsonl`
- Canonical S08 source repository: `recovered-repos/round2-xen_arm64-778090a1/recovered-hypervisor/`
- S08 staged source snapshot: `cases/round2-xen_arm64-778090a1/stages/S08/recovered-hypervisor/`
- S08 unresolved index: `cases/round2-xen_arm64-778090a1/stages/S08/unresolved-index.jsonl`
- S08 source repo delivery manifest: `cases/round2-xen_arm64-778090a1/stages/S08/source-repo-delivery.json`
- Oracle score: `cases/round2-xen_arm64-778090a1/validation/oracle/codegen-ready-oracle-score.json`

## Initial Results Before S03-RW2

- Function clusters: 2
- Codegen-ready lifted functions: 9
- Source files emitted: 2 `.c` and 2 `.h`
- Fake stub files emitted: 0
- Boundary-blocked or unresolved entries: 3

Codegen-ready functions:

- `0x198` -> boot/MMU secondary entry
- `0x1ec` -> CPU mode check
- `0x238` -> CPU initialization
- `0x368` -> early page table creation
- `0x5c4` -> MMU enable path
- `0x604` -> barrier helper
- `0x5f314` -> maintenance interrupt/timer slot initialization
- `0x661a0` -> secondary CPU start path
- `0x66600` -> timer interrupt initialization

Boundary-blocked or unresolved entries:

- `0x160`: no recovered function boundary/decompile in the target IDB.
- `0x634`: target IDB reported a mismatched containing function, not an exact function root.
- `0x708`: target IDB reported a mismatched containing function, not an exact function root.

## Workflow and Skill changes validated

1. S08 source generation must be gated by S07 `codegen-ready-functions.jsonl`.
2. A function is not codegen-ready unless the recovered IDA function start exactly equals the requested root address.
3. Hex-Rays output from a containing function is not sufficient evidence for source emission at a mid-function target.
4. Template-derived source functions must be removed when their corresponding address is not codegen-ready in the current case.
5. Generated source READMEs must be case-specific and must reference current-case artifacts, not template or previous-round artifacts.
6. Oracle labels may annotate validation reports, but must not change production-stage evidence, stage gates, or generated source directly.

## Validation

The Round 2 generated artifacts passed:

- JSON/JSONL parse validation across the case directory.
- Script bytecode validation for the v2 source generator and Round 2 extraction helpers.
- Source-pruning check: `0x160` and `0x708` template functions were not present in the Round 2 source tree after generation.

## Next improvement target

The next useful improvement is an S03/S07 boundary-repair loop for mid-function ARM64 entrypoints, especially local-label branch targets that Oracle confirms as real functions in lab runs but that production must infer from control-flow and prologue/epilogue evidence alone.

## S03-RW2 Boundary Repair Follow-up

S03-RW2 used target-only IDA evidence to repair the three blocked entries:

- `0x160`: recovered as an exact boot-entry function after removing wrong ownership around the early boot range.
- `0x634`: removed from the unrelated `sub_2B0` tail chunks and recreated as an exact bounded MMU handoff helper.
- `0x708`: split from the `0x6c4` containing function as an exact shared TTBR/SCTLR switch suffix entry.

Artifacts:

- Diagnosis: `cases/round2-xen_arm64-778090a1/stages/S03/s03-rw1-boundary-diagnose.json`
- Transaction/readback: `cases/round2-xen_arm64-778090a1/stages/S03/s03-rw2-boundary-repair-transaction.json`
- Refreshed IDA export: `cases/round2-xen_arm64-778090a1/stages/S07/ida-decompile-export-rw1.json`

Post-repair results:

- Codegen-ready lifted functions: 12
- Source implementations emitted: 12
- Boundary-blocked or unresolved entries: 0
- Codegen-ready functions without source implementation: 0
- Fake stub files emitted: 0
- Oracle exact-address matches: 11 / 12
- Canonical source repository contains 2 `.c`, 2 `.h`, `Makefile`, linker script, and `README.md`; it contains no JSON/JSONL/IDA/SQLite intermediate artifacts.

Workflow rule learned:

Containing-function decompile output is not codegen evidence for a candidate root. However, a containing-function/chunk mismatch is strong S03 repair evidence. The repair loop must inspect chunks, remove wrong tail ownership, create exact function roots, save the IDB, and verify readback before S07/S08 consumption.

## Corpus-wide Follow-up

The workflow was then expanded from selected-target recovery to corpus-wide recovery.

Artifacts:

- Full S03 function export: `cases/round2-xen_arm64-778090a1/stages/S03/functions.jsonl`
- Full S03 call graph: `cases/round2-xen_arm64-778090a1/stages/S03/call-graph.json`
- Full S04 architecture events: `cases/round2-xen_arm64-778090a1/stages/S04/architecture-events.jsonl`
- Full S07 decompile export: `cases/round2-xen_arm64-778090a1/stages/S07/decompile-export-full.json`
- Canonical source repo: `recovered-repos/round2-xen_arm64-778090a1/recovered-hypervisor/`

Corpus-wide results:

- IDA functions exported: 2020
- Decompiled functions: 2020
- Generated source-map functions: 2020
- Source status: `source_corpus_lifted`
- `semantic-c`: 330
- `lifted-c`: 1690
- `asm-fallback`: 0
- Source files in canonical repo: 17
- `.c` files: 14
- `.h` files: 1
- Forbidden JSON/JSONL/IDA/SQLite artifacts in source repo: 0
- Pseudocode review-view coverage: 100%
- Wrapper-body ratio: 100%
- Semantic ratio: 16.34%

Workflow rule learned:

S10 must preserve the upstream source status. A coverage-first full corpus lift is not `source_repo_ready`; it is `source_corpus_lifted` until semantic naming, type recovery, readability, and audit gates improve.

Additional readability rule learned:

Embedding Hex-Rays pseudocode review blocks makes the full corpus auditable and gives each function a visible recovered logic shape, but it is not equivalent to semantic source. A function remains `lifted-c` while its executable body is still a generic wrapper or while IDA residue dominates names/types/globals.

## Semantic Rewrite Planning Follow-up

S09 now emits a debt-ranked rewrite plan:

- Plan JSON: `cases/round2-xen_arm64-778090a1/stages/S09/semantic-rewrite-plan.json`
- Plan Markdown: `cases/round2-xen_arm64-778090a1/stages/S09/semantic-rewrite-plan.md`

Top rewrite batches in the Round 2 run:

1. `core/runtime/runtime.c`: 1231 functions, 1221 lifted, 10 semantic-labeled wrappers.
2. `arch/arm64/mmu/cache.c`: 374 functions, 374 lifted.
3. `core/runtime/percpu.c`: 288 functions, 288 semantic-labeled wrappers.
4. `arch/arm64/boot/boot.c`: 53 functions, 53 lifted.
5. `drivers/gic/interrupt.c`: 26 functions, 26 lifted.

Workflow rule learned:

Semantic labels are not sufficient. If the executable body is still a generic wrapper, the function remains readability debt even when the function-map class says `semantic-c`.

## S08 Semantic Rewrite Batch RW1

The first conservative semantic rewrite batches targeted `core/runtime/runtime.c` using only simple one-statement Hex-Rays return patterns.

Artifacts:

- Rewrite script: `skills/synthesize-hypervisor-repository/scripts/apply_semantic_rewrite_batch.py`
- Rewrite index: `cases/round2-xen_arm64-778090a1/stages/S08/semantic-rewrite-index.jsonl`
- Rewrite summary: `cases/round2-xen_arm64-778090a1/stages/S08/semantic-rewrite-summary.json`

RW1 first pass results:

- Selected functions: 50
- Applied rewrites: 50
- Rewrite kinds:
  - `return_direct_call`: 32
  - `return_constant`: 14
  - `return_indirect_call`: 2
  - `return_global`: 2
- `semantic-c`: 330 -> 380
- `lifted-c`: 1690 -> 1640
- wrapper-body ratio: 100.00% -> 97.52%

RW1 second pass results:

- Selected functions: 38
- Applied rewrites this pass: 38
- Applied rewrites cumulative: 88
- Rewrite kinds:
  - `return_constant`: 20
  - `return_direct_call`: 18
- `semantic-c`: 418
- `lifted-c`: 1602
- wrapper-body ratio: 95.64%

The second pass found fewer safe functions because most remaining runtime functions contain complex expressions or control flow and must stay `lifted-c` until a stronger translator/type propagation pass exists.

Workflow rule learned:

`recovered_trace()` is traceability metadata and should not be counted as a wrapper body. S09 wrapper-body ratio must count generic `recovered_mark_*()` bodies instead.

## S08 ARM64 Architecture Rewrite Batch RW1

The first ARM64 architecture rewrite batch targeted `arch/arm64/mmu/cache.c` using only small barrier/cache/TLB helper patterns.

Artifacts:

- Rewrite script: `skills/synthesize-hypervisor-repository/scripts/apply_arm64_arch_rewrite_batch.py`
- Rewrite index: `cases/round2-xen_arm64-778090a1/stages/S08/arm64-arch-rewrite-index.jsonl`
- Rewrite summary: `cases/round2-xen_arm64-778090a1/stages/S08/arm64-arch-rewrite-summary.json`

RW1 results:

- Selected functions: 20
- Applied rewrites: 20
- Rewrite kinds:
  - `arm64_arch_return_direct_call`: 16
  - `arm64_arch_jumpout`: 3
  - `arm64_arch_fallthrough`: 1
- `semantic-c`: 418 -> 438
- `lifted-c`: 1602 -> 1582
- wrapper-body ratio: 95.64% -> 94.65%

Workflow rule learned:

Small `DSB`/`ISB`/`TLBI`/cache-maintenance helpers can be rewritten safely as architecture helper calls. Complex page-table walkers, lock paths, loops, and mixed memory stores must remain `lifted-c` until stronger type/dataflow recovery exists.

## S08 per-CPU Rewrite Batch RW1

The first per-CPU rewrite batch targeted `core/runtime/percpu.c` to reduce semantic-label/body mismatch.

Artifacts:

- Rewrite script: `skills/synthesize-hypervisor-repository/scripts/apply_percpu_rewrite_batch.py`
- Rewrite index: `cases/round2-xen_arm64-778090a1/stages/S08/percpu-rewrite-index.jsonl`
- Rewrite summary: `cases/round2-xen_arm64-778090a1/stages/S08/percpu-rewrite-summary.json`

RW1 results:

- Selected functions: 16
- Applied rewrites: 16
- Rewrite kinds:
  - `percpu_base_read`: 1
  - `percpu_callsite`: 15
- `semantic-c`: unchanged at 438 because these functions were already labeled semantic.
- wrapper-body ratio: 94.65% -> 93.86%
- `core/runtime/percpu.c` semantic-labeled wrapper mismatch: 288 -> 272

Workflow rule learned:

Some files can have high semantic-c ratio and still be low-quality because their executable bodies remain wrappers. S09 must continue tracking semantic-label/body mismatch separately from class counts. Full Hex-Rays expressions should stay in evidence and pseudocode review blocks; generated executable bodies should use clean summaries to avoid increasing IDA residue.

## S08 Boot Rewrite Batch RW1

The first boot rewrite batch targeted `arch/arm64/boot/boot.c` using small DAIF, CurrentEL, MPIDR/WFE, and ELR handoff patterns.

Artifacts:

- Rewrite script: `skills/synthesize-hypervisor-repository/scripts/apply_boot_rewrite_batch.py`
- Rewrite index: `cases/round2-xen_arm64-778090a1/stages/S08/boot-rewrite-index.jsonl`
- Rewrite summary: `cases/round2-xen_arm64-778090a1/stages/S08/boot-rewrite-summary.json`

RW1 results:

- Selected functions: 11
- Applied rewrites: 11
- Rewrite kinds:
  - `boot_daif_call_chain`: 8
  - `boot_secondary_wait`: 1
  - `boot_currentel_guard`: 1
  - `boot_elr_handoff`: 1
- `semantic-c`: 438 -> 449
- `lifted-c`: 1582 -> 1571
- wrapper-body ratio: 93.86% -> 93.32%
- `arch/arm64/boot/boot.c` wrapper ratio: 100.00% -> 79.25%

Workflow rule learned:

Boot entry and handoff helpers can be made more readable by preserving architectural actions (`DAIF`, `CurrentEL`, `MPIDR_EL1`, `WFE`, `ELR_EL2`) as explicit helper calls. Larger CPU/platform initialization remains `lifted-c` until structure/type recovery is strong enough.

## S08 Semantic Naming and Source-View Cleanup RW1

The first naming pass targeted functions that already had applied semantic rewrite evidence.

Artifacts:

- Naming script: `skills/synthesize-hypervisor-repository/scripts/apply_semantic_names.py`
- Naming index: `cases/round2-xen_arm64-778090a1/stages/S08/semantic-name-index.jsonl`
- Naming summary: `cases/round2-xen_arm64-778090a1/stages/S08/semantic-name-summary.json`
- Source-view cleanup script: `skills/synthesize-hypervisor-repository/scripts/clean_semantic_source_view.py`
- Cleanup index: `cases/round2-xen_arm64-778090a1/stages/S08/source-view-cleanup-index.jsonl`
- Cleanup summary: `cases/round2-xen_arm64-778090a1/stages/S08/source-view-cleanup-summary.json`

RW1 results:

- Renamed source symbols: 135
- Source occurrences replaced: 411
- Inline Hex-Rays blocks removed for semantic functions: 135
- generic source-symbol ratio after RW1: 89.95%
- pseudocode review-view ratio after RW1: 93.32%

Workflow rule learned:

Final readability requires a dedicated naming/presentation pass. Function body rewrites alone do not fix `*_helper_0001`, `sub_*`, `qword_*`, or large inline Hex-Rays residue. S09 must block `source_repo_ready` while generic source-symbol ratio remains high. Source-view cleanup must be strictly local to the immediately adjacent pseudocode block; an earlier greedy cleanup bug showed that cross-function deletion can corrupt source layout.
