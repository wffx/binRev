# S08: Function-Level Source Lifting and Repository Synthesis

S08 generates source code only from function-level evidence.

## Goal

Produce a source repository whose `.c`, `.h`, and `.S` files correspond to IDA-derived functions or explicit assembly fallback regions.

## Inputs

- S07 `codegen-ready-functions.jsonl`.
- IDA decompile/disassembly exports.
- S06 type candidates and structure layouts.

## Outputs

- `recovered-hypervisor/`
- `function-map.json`
- `source-map.json`
- `unresolved-index.jsonl`
- `source-quality-report.json`

## Source classes

- `lifted-c`: close to IDA/Hex-Rays and assembly.
- `semantic-c`: cleaned C with evidence-backed names/types.
- `asm-fallback`: assembly-sensitive source.
- `unresolved`: no source generated.

For corpus-first output, `lifted-c` may include a non-compiling Hex-Rays pseudocode review block next to a conservative generated body. This improves auditability because every function has a readable decompiler view, but it does not make the function semantic-C.

## Boundary

Do not generate fake `.c` / `.h` files for unresolved internal modules.

## Corpus-wide rule

S08 status must reflect coverage:

- `source_slice_ready`: selected subset only.
- `source_corpus_lifted`: every function has source/asm/unresolved mapping; readability still needs refinement.
- `source_repo_semantic_partial`: corpus exists and high-confidence modules have semantic names/types.
- `source_repo_ready`: coverage and readability gates pass.

S08 must not call a small number of generated `.c`/`.h` files a full source repository. The canonical source repository must remain clean: no JSON, JSONL, SQLite, IDA database, or intermediate analysis artifacts.

S08 must also distinguish source coverage from source quality. A repository with all functions mapped and all pseudocode views present is `source_corpus_lifted` until S09 readability gates show that wrapper bodies and IDA residue have been reduced enough for `source_repo_semantic_partial` or `source_repo_ready`.

## Semantic rewrite loop

After corpus lifting, S08 may run small semantic rewrite batches selected by S09. A batch may promote functions from `lifted-c` to `semantic-c` only when the generated executable body is replaced, not merely when the function-map label changes.

Initial safe rewrite classes:

- return constant;
- return global object;
- return direct mapped function call;
- return indirect function pointer/global call.
- small ARM64 barrier/cache/TLB helper with optional mapped call or JUMPOUT.
- short ARM64 system-register read/write helper with ISB/DSB/DMB barriers and optional direct calls.
- short straight-line diagnostic/logging sequence with `sub_1C18(...)`-style calls.
- one-statement TPIDR_EL2 per-CPU read/callsite.
- small boot/init DAIF, CurrentEL, MPIDR/WFE, or ELR handoff helper.
- high-confidence diagnostic or boot summary body when explicit strings/calls identify behavior but full dataflow remains too complex.

Outputs for each batch:

- `semantic-rewrite-index.jsonl`
- `semantic-rewrite-summary.json`
- `arm64-arch-rewrite-index.jsonl`
- `arm64-arch-rewrite-summary.json`
- `percpu-rewrite-index.jsonl`
- `percpu-rewrite-summary.json`
- `boot-rewrite-index.jsonl`
- `boot-rewrite-summary.json`
- `sysreg-rewrite-index.jsonl`
- `sysreg-rewrite-summary.json`
- `log-sequence-rewrite-index.jsonl`
- `log-sequence-rewrite-summary.json`
- `diagnostic-summary-rewrite-index.jsonl`
- `diagnostic-summary-rewrite-summary.json`
- `diagnostic-summary-candidates.jsonl`
- `diagnostic-summary-candidates-summary.json`
- `rewrite-reconcile-summary.json`
- `semantic-name-index.jsonl`
- `semantic-name-summary.json`
- `evidence-semantic-name-index.jsonl`
- `evidence-semantic-name-summary.json`
- `candidate-semantic-name-index.jsonl`
- `candidate-semantic-name-summary.json`
- `simple-pseudocode-name-index.jsonl`
- `simple-pseudocode-name-summary.json`
- `module-rehome-index.jsonl`
- `module-rehome-summary.json`
- `source-symbol-repair-index.jsonl`
- `source-symbol-repair-summary.json`
- `source-symbol-repair-normalization-index.jsonl`
- `source-symbol-repair-normalization-summary.json`
- `duplicate-wrong-file-cleanup-index.jsonl`
- `duplicate-wrong-file-cleanup-summary.json`
- `duplicate-wrong-file-removed-blocks.jsonl`
- `global-alias-index.jsonl`
- `global-alias-summary.json`
- `offset-field-annotation-index.jsonl`
- `offset-field-annotation-summary.json`
- `lifted-pseudocode-review.jsonl`
- `lifted-pseudocode-review-summary.json`
- `source-view-cleanup-index.jsonl`
- `source-view-cleanup-summary.json`
- `source-class-sync-index.jsonl`
- `source-class-sync-summary.json`

Exit condition for a batch: S09 readability metrics show a measurable decrease in wrapper-body ratio or IDA residue, and function-map labels agree with source bodies.

Run rewrite reconciliation after each batch. The reconciliation step must make applied rewrite indexes, `function-map.json`, `source-map.json`, and `source-quality-report.json` agree before S09/S10 packaging.

Run source-class synchronization after reconciliation and naming/presentation passes. `function-map.json` is the authoritative source for `output_class` and `confidence`; `source-map.json` and source evidence comments must match it before S09. This prevents a semantic body rewrite from leaving stale comments such as `class lifted-c` beside a `semantic-c` function.

## Naming and source presentation

Semantic rewrites must be followed by semantic naming. Address-like, IDA-like, and generated helper names belong in evidence maps, not as the final primary source symbols.

If a function is still `lifted-c` but has strong architecture/string evidence from S04/S07, S08 may apply evidence-backed naming without promoting `output_class`. This is the preferred way to reduce names such as `interrupt_helper_0001`, `timer_control_0001`, or `runtime_helper_0001` while preserving honest code-quality status.

Evidence-backed naming must improve semantic specificity. Broad anchors such as `TPIDR_EL2` are useful context, but by themselves they must not rename one generic symbol family into another generic family such as `percpu_access_current_cpu_state_N`. Such low-value renames should be rolled back and captured in S08 evidence.

Diagnostic summary rewrites may replace empty wrappers for functions with explicit strings such as debug-key toggles, console log-level updates, delayed reboot/noreboot handlers, saved CPU register dumps, unexpected interrupt diagnostics, division-by-zero trap reports, credit scheduler initialization, printk-style variadic logging, CPU bring-up, diagnostic keyhandlers, memory/version banners, scheduler state printers, or EL2 fault reporting. They must preserve full pseudocode evidence externally and must not pretend to recover every branch or data structure field. When the summary establishes a clear responsibility, S08 should also rename generic symbols and callsites through `semantic-name-index.jsonl`.

S08 should generate diagnostic-summary candidates before expanding a rewrite rule. Candidate generation is read-only and records risk. Low-risk candidates may feed a narrow rewrite rule; high-risk candidates stay lifted until stronger type/control-flow evidence exists. Trap-only algorithmic functions are not diagnostic summaries.

Candidate-driven naming may be applied to high-risk candidates when evidence strongly identifies responsibility but the body remains lifted. This is a naming-only readability improvement: it updates source symbols and maps, records `candidate-semantic-name-*` evidence, and must not promote the function from `lifted-c`.

Simple-pseudocode naming may be applied when S07 pseudocode reduces to a strict one-statement body, such as a pure constant return or direct tail call. This reduces unhelpful helper names without claiming high-level semantics. Complex functions with branches, loops, memory ownership, or hardware side effects must not be named by this pass.

Named module families may be rehomed into clearer source files after naming. Rehome is organization-only: it moves function blocks, updates maps and source file lists, records `module-rehome-*` evidence, and must preserve body text and output class. The initial supported example is moving `dt_*` helpers to `platform/unknown/device_tree.c`.

After rehome, S08 must perform symbol readback. If a source block was lost, restore it from `function-map.json` with `source-symbol-repair-*` evidence. Repair blocks are conservative wrappers and do not improve semantic quality; they only restore full function coverage.

If readback repair creates or reveals duplicate source-symbol definitions, S08 must remove only the noncanonical copy whose file does not match `function-map.json`. The cleanup records `duplicate-wrong-file-cleanup-*` evidence and archives removed source blocks under `duplicate-wrong-file-removed-blocks.jsonl` for audit; it must not change source-map ownership or output classes.

When S07 decompiler evidence is available for source-symbol repair addresses, S08 should normalize those emergency repair wrappers back into ordinary lifted source views. Normalization restores the `lifted Hex-Rays` review block and removes the repair marker, but it does not promote the function to semantic source or change source ownership. After normalization, S08 should externalize inline `lifted Hex-Rays` review blocks into evidence so user-facing `.c` files stay readable while audit coverage remains high.

If S06 has global-object candidates, S08 may apply presentation aliases for high-frequency IDA globals. Aliases reduce visible `qword_*`, `dword_*`, and `byte_*` residue in source, but they are not confirmed variable names and must remain traceable to original IDA globals.

If S06 has offset-family candidates, S08 may annotate visible base+offset accesses with candidate field comments, for example `candidate_runtime_a1_object.field_0x18`. This is a presentation-only pass: it must keep the original Hex-Rays expression intact, must not annotate inside strings or historical pseudocode comments, must be idempotent, and must not promote `output_class` or claim confirmed structure ownership.

If lifted-only functions still need decompiler review text, S08 may move inline `#if 0` Hex-Rays views from source files into `lifted-pseudocode-review.jsonl`. This keeps the delivered source repository source-like while preserving audit coverage. The function remains `lifted-c`, and S09 must count externalized pseudocode as evidence coverage, not as semantic source quality.

Inline Hex-Rays pseudocode may stay for lifted-only functions, but semantic functions should move that review text out of user-facing source once evidence is preserved in S07/S08 artifacts.
