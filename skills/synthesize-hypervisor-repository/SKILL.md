---
name: synthesize-hypervisor-repository
description: "Synthesize the recovered hypervisor source repository from accepted workflow evidence. Use in S07 to emit freestanding AArch64 source only for codegen-ready or explicitly asm-fallback functions, preserve evidence maps, and avoid fake internal module stubs or invented unresolved logic."
---

# Synthesize Hypervisor Repository

## Purpose

Convert accepted recovery models into a readable, build-oriented repository skeleton. This Skill does not call IDA write operations and does not perform new reverse engineering.

If S07 is `review_seed_ready_production_blocked` and its S08 review-seed gate is ready, generate an unresolved/review-seed repository scaffold only. Do not synthesize confirmed C or assembly semantics from lifecycle/HKIP hypotheses.

## Inputs

Require accepted:

- `S03/program-model.json`
- `S04/architecture-model.json`
- `S05/runtime-object-model.json`
- `S06/service-model.json`
- `S07/security-lifecycle-model.json`
- stage evidence/decision/unknown indexes

Review-seed mode requires:

- `S07/stage-manifest.json`
- `S07/security-lifecycle-model.json`
- `S07/lifecycle-model.json`
- `S07/hkip-model.json`
- `S07/resource-transitions.jsonl`

## Workflow

1. Enforce model gates.
   - Use only accepted S03-S07 models.
   - If a required model is missing or forward-test only, generate an unresolved-only package or block S08.
   - If S07 allows only review-seed S08, run `scripts/generate_s08_review_seed_repository.py`.

2. Create repository layout.
   - Emit `arch/arm64`, `core`, `security/hkip`, `drivers`, `platform/unknown`, `include`, `recovered/asm_fallback`, `linker`, `tests`, and `.recovery`.

3. Synthesize source units.
   - Generate C only for confirmed or inferred-C functions with evidence.
   - Use `.S` fallback for world-switch, exception vectors, atomic fragments, and unresolved assembly-sensitive paths.
   - Use explicit failing stubs for external platform/hardware dependencies.
   - In review-seed mode, generate only explicit unresolved/failing stubs and traceable scaffold files.

4. Preserve traceability.
   - Every generated file/function/type must reference address ranges and evidence IDs.

## Outputs

Produce:

- `S07/recovered-repo/`
- `S07/recovery-index.json`
- `S07/build-manifest.json`
- `S07/unresolved-index.jsonl`

## Boundaries

- Do not invent business logic for unresolved functions.
- Do not aim for byte-identical Image reconstruction in S08.
- Do not write IDA.
- Do not convert `model_hypothesis` lifecycle, scheduler, interrupt, Stage-2, or HKIP records into source implementations.

## S08 function-level source lifting

This Skill generates source only from `S07/codegen-ready-functions.jsonl` and IDA decompile/disassembly exports.

Do not create a broad module tree just because the domain has CPU, VM, HKIP, scheduler, interrupt, or Stage-2 concepts. Create source files only when at least one function in that file is `codegen-ready` or `asm-fallback`.

Require exact function-boundary evidence before lifting Hex-Rays output. If IDA only provides a containing function whose start differs from the candidate root, record the candidate in `S07/unresolved-index.jsonl` and do not emit source for that address.

Primary outputs:

- `recovered-repos/<case-id>/recovered-hypervisor/` as the canonical user-facing source repository
- `S07/recovered-hypervisor/` as a staged copy inside the evidence workspace
- `S07/function-map.json`
- `S07/source-map.json`
- `S07/source-quality-report.json`
- `S07/unresolved-index.jsonl`
- `S07/source-repo-delivery.json`

The canonical source repository must be source-first: include `.c` and `.h` files and only source/build-facing support files such as `README.md`, `Makefile`, linker scripts, or assembly fallback files. Keep JSON/JSONL/SQLite/IDA artifacts in `cases/<case-id>/stages`; do not describe the case evidence directory as the source repository.

For corpus-wide first-pass recovery, run `scripts/generate_corpus_source_repo.py --case-id <case-id>` after `S07/decompile-export-full.json` exists. This mode must generate source-map entries for every S03 function and set status to `source_corpus_lifted` unless semantic coverage/readability gates justify a stronger status. Do not report `source_repo_ready` from coverage-first lifted code alone.

In corpus-wide first-pass mode, include a non-compiling Hex-Rays pseudocode review block for each lifted function when decompiler text is available. Treat this as audit support only: it may raise pseudocode-view coverage, but it does not promote the function from `lifted-c` to `semantic-c`.

After corpus lift, prioritize semantic rewrite for modules with the highest readability debt. Replace generic wrapper bodies with safe translated Hex-Rays logic where evidence is adequate, promote repeated globals/offset families into named objects, and rerun S09 readability audit after each rewrite batch.

For conservative batch rewrites, run `scripts/apply_semantic_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only for simple one-statement Hex-Rays return patterns such as constants, globals, direct calls, and indirect calls. The script must update source bodies and S08 function-map/source-quality evidence together. Do not use it for complex control flow.

For small ARM64 architecture helpers, run `scripts/apply_arm64_arch_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only when the body contains barrier/cache/TLB operations plus an optional direct call or JUMPOUT. Do not use it for page-table walkers, locks, loops, stores, or mixed dataflow.

For per-CPU semantic-label/body mismatch, run `scripts/apply_percpu_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only for one-statement returns that explicitly reference `TPIDR_EL2`. Preserve full Hex-Rays text in evidence/indexes; keep executable source bodies clean and avoid duplicating IDA residue in strings.

For boot/init helpers, run `scripts/apply_boot_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only for small DAIF masking, CurrentEL/MPIDR/WFE guard, ELR handoff, and short boot call-chain functions. Leave complex CPU/platform/device initialization as `lifted-c`.

For short ARM64 system-register helpers, run `scripts/apply_sysreg_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only for small `_ReadStatusReg` / `_WriteStatusReg` sequences, ISB/DSB/DMB barriers, and optional direct calls. This is especially useful for GIC/timer/EL2 helper functions. Skip loops, switches, ordinary stores, mixed memory dataflow, and complex interrupt state machines. If a direct call has original arguments, preserve the whole call expression through `recovered_direct_call(ctx, "sub_x(args)", addr)` rather than pretending it is a no-argument recovered source call.

For short diagnostic/logging helpers, run `scripts/apply_log_sequence_rewrite_batch.py --case-id <case-id> --source-file <path> --max-functions <n>`. Use it only for straight-line `sub_1C18(...)`-style logging/diagnostic sequences plus optional direct calls. Preserve original call expressions as summaries. Skip branches, loops, switches, stores, varargs implementation internals, and mixed dataflow.

For high-confidence diagnostic or boot functions whose strings clearly identify behavior but whose full dataflow is too complex, run `scripts/apply_diagnostic_summary_rewrite_batch.py --case-id <case-id> --max-functions <n>`. This pass may replace empty wrapper bodies with a small summary body using `recovered_log` and evidence-backed direct-call summaries. It must keep full pseudocode in S08 evidence and must not claim every branch or structure field was recovered. Known safe families include debug-key mode toggles, console log-level updates, delayed reboot/noreboot handlers, saved CPU register dumps, unexpected interrupt diagnostics, division-by-zero trap reports, credit-scheduler initialization summaries, printk-style variadic logging frontends, CPU bring-up diagnostics, memory/version banners, scheduler state printers, and EL2 fault reports when explicit strings/calls identify the behavior.

Before broadening diagnostic-summary rewrites, run `scripts/propose_diagnostic_summary_candidates.py --case-id <case-id> --source-file <path> --limit <n>`. This read-only planner mines externalized Hex-Rays evidence for string/log/trap-heavy lifted functions and writes `diagnostic-summary-candidates.jsonl`. Treat `risk=high` as review-only unless a new narrow rule is added and validated. Trap-only functions without strings/log calls are not diagnostic-summary candidates.

After any rewrite batch, run `scripts/reconcile_rewrite_evidence.py --case-id <case-id>` before S09. This reconciles rewrite indexes into `function-map.json`, `source-map.json`, and `source-quality-report.json`, and prevents interrupted or repeated batches from leaving source/evidence/map inconsistencies.

After rewrite reconciliation and any naming/presentation pass, run `scripts/sync_source_classes.py --case-id <case-id>` before S09. Treat `function-map.json` as authoritative for `output_class` and `confidence`; synchronize `source-map.json` and source evidence comments to it. This is required because a rewrite may correctly promote a function to `semantic-c` while older source comments still say `class lifted-c`.

After rewrite evidence exists, run `scripts/apply_semantic_names.py --case-id <case-id>` to replace generic helper/access source symbols with evidence-backed names. Rename source bodies, callsites, `function-map.json`, and `source-map.json` together. Do not rename functions without rewrite, type, architecture, string, or callgraph evidence. Diagnostic-summary rewrites may also drive semantic names when the summary has an explicit behavior label, for example `scheduler_initialize_credit_state` or `runtime_vprintk_frontend`.

When a candidate index identifies strong responsibility evidence but the function remains too complex for semantic body rewrite, run `scripts/apply_candidate_semantic_names.py --case-id <case-id> --max-renames <n>`. This pass may rename lifted functions such as device-tree range parsers or register dump helpers, but it must not promote `output_class`. Record names in `candidate-semantic-name-index.jsonl` and append trace rows to `evidence-semantic-name-index.jsonl`.

After evidence-backed names expose a coherent module family, run `scripts/rehome_named_module_functions.py --case-id <case-id> --prefix <prefix>` to move those functions into a clearer source file. This is source organization only: update `function-map.json`, `source-map.json`, source file lists, and `module-rehome-index.jsonl`, but do not change function bodies or promote `output_class`. The first supported family is `dt_` to `platform/unknown/device_tree.c`.

After any rehome pass, immediately run S09 source readback. If symbols disappeared, run `scripts/repair_missing_source_symbols.py --case-id <case-id>` and rerun `scripts/sync_source_classes.py --case-id <case-id>` before packaging. Source-symbol repair restores conservative wrappers from `function-map.json`; it is coverage repair only and must not be counted as semantic body recovery.

If S09 reports duplicate primary source-symbol definitions, run `scripts/remove_duplicate_wrong_file_functions.py --case-id <case-id>`. This cleanup uses `function-map.json` as the canonical source-file authority and removes only noncanonical duplicate definitions when the canonical file already contains the same symbol. It must not rename functions, change output classes, or move source-map ownership. If canonical definitions are missing but noncanonical definitions exist, restore canonical wrappers first with `repair_missing_source_symbols.py`, then run duplicate cleanup so source-map readback remains valid. Duplicate cleanup must archive removed blocks to S08 evidence when it deletes source text.

After repair/duplicate cleanup, if `S07/decompile-export-full.json` contains decompiler evidence for repair addresses, run `scripts/normalize_source_symbol_repairs.py --case-id <case-id>`. This replaces emergency repair wrappers with ordinary lifted source views and restored pseudocode review blocks. It removes the repair marker but does not promote `output_class`, rename symbols, or invent semantics.

When externalizing inline pseudocode review blocks, use function-definition anchored cleanup only. Do not use a broad cross-function regex that searches from `#if 0` to the next `uintptr_t`; if an evidence comment sits between `#endif` and a function definition, such regexes can swallow intervening functions. Always rerun S09 symbol readback immediately after source-view cleanup.

After S04/S07 evidence exists, run `scripts/apply_evidence_semantic_names.py --case-id <case-id>` to reduce remaining generic names that have strong architecture or string evidence but whose bodies are still `lifted-c`. This pass may rename symbols such as `interrupt_helper_0001`, `timer_control_0001`, or `runtime_helper_0001`, but must not promote `output_class`. Keep address/IDA names in comments and maps, not primary source symbols.

For generic helpers whose S07 pseudocode is mechanically simple, run `scripts/apply_simple_pseudocode_names.py --case-id <case-id>`. This pass may rename only strict one-statement functions such as pure constant returns or pure direct tail calls. It is a naming-only readability pass and must not infer subsystem semantics from complex control flow.

Do not rename from one generic family to another generic family merely because a broad architecture anchor appears. In particular, `TPIDR_EL2` alone is not enough to rename a function to `percpu_access_current_cpu_state_N` or `runtime_access_current_cpu_state_N`; require additional string, callgraph, module, or data-layout evidence. If a naming pass only renumbers generic symbols, roll it back and record a rollback summary.

After S06 global-object candidates exist, run `scripts/apply_global_aliases.py --case-id <case-id>` to replace high-frequency `qword_*`, `dword_*`, and `byte_*` names in user-facing `.c` source with stable presentation aliases such as `timer_global_state_001`. This pass must not promote `output_class`; original IDA names must remain in `S06/global-object-model.json`, `S07/global-alias-index.jsonl`, and `include/recovered/recovered_objects.h` comments.

After S06 offset-family candidates exist, run `scripts/annotate_offset_field_accesses.py --case-id <case-id> --max-annotations <n>` to add presentation-only comments beside real base+offset dereferences, such as `candidate_runtime_a1_object.field_0x18`. This pass must be idempotent, must first remove its old annotations, must not annotate inside string literals or historical pseudocode comments, and must not promote `output_class` or claim confirmed structure ownership.

When lifted-only inline `#if 0` pseudocode makes the source repository unreadable, run `scripts/extract_lifted_pseudocode_views.py --case-id <case-id> --max-functions <n>` to move those review blocks into `S07/lifted-pseudocode-review.jsonl`. This keeps source files source-like while preserving decompiler evidence. The function remains `lifted-c`; do not count externalized pseudocode as semantic source.

For user-facing readability, run `scripts/clean_semantic_source_view.py --case-id <case-id>` after semantic names are applied. With this semantic-clean script, remove inline Hex-Rays pseudocode only for functions that already have semantic body/name evidence. Lifted-only functions must use `extract_lifted_pseudocode_views.py` if their review blocks are externalized.

After every semantic rewrite batch:

1. rerun S09 readability audit;
2. rerun `reconcile_rewrite_evidence.py`;
3. rerun `sync_source_classes.py`;
4. rerun S09 semantic rewrite planning;
5. preserve the status as `source_corpus_lifted` unless readiness gates actually pass.

Allowed source classes:

- `lifted-c`
- `semantic-c`
- `asm-fallback`

Forbidden:

- fake `.c` / `.h` files for unresolved internal modules;
- source files generated only from module names, large-model guesses, or review-seed business semantics.
- treating pseudocode review comments or wrapper bodies as semantic source.
