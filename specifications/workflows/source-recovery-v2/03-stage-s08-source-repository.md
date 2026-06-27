# Stage S08: Function-Level Source Lifting and Repository Synthesis

## Goal

Generate source from IDA-derived function evidence for the whole corpus.

## Output classes

- `lifted-c`: close to Hex-Rays/assembly with evidence comments.
- `semantic-c`: cleaned human-readable C after type/name propagation.
- `asm-fallback`: assembly-sensitive regions.
- `unresolved`: no source generated.

Corpus-first lifted source may include a non-compiling Hex-Rays pseudocode
review view beside a conservative wrapper body. This is useful for audit, but
it is still `lifted-c`: it must not be counted as semantic source until the
executable body is rewritten with evidence-backed names, types, globals, and
structure fields.

## Forbidden output

- fake `.c` / `.h` stubs for unresolved internal modules;
- a small source slice reported as a complete recovered source repository.

## Outputs

- canonical clean source repository under
  `recovered-repos/<case-id>/recovered-hypervisor/`;
- staged source snapshot under the case evidence workspace;
- `function-map.json`;
- `source-map.json`;
- `unresolved-index.jsonl`;
- `source-quality-report.json`.

## Repository status values

- `source_slice_ready`: only a selected subset has source.
- `source_corpus_lifted`: all IDA functions have source/asm/unresolved mapping,
  with coverage prioritized over readability.
- `source_repo_semantic_partial`: corpus exists and high-confidence modules have
  semantic names/types.
- `source_repo_ready`: coverage, semantic naming, type recovery, source purity,
  and audit gates all pass.

## Exit condition

Every S07 function is represented in `function-map.json` as `semantic-c`,
`lifted-c`, `asm-fallback`, or `unresolved`. The canonical source repository
must contain real source/build files, including `.c` and `.h`, and must not
contain JSON/JSONL/IDA/SQLite intermediate artifacts.

## Rewrite and naming rules

S08 semantic rewrite batches must update source and evidence atomically. A
rewrite can promote a function to `semantic-c` only when the generated body
stops being a generic wrapper and preserves a simple evidence-backed behavior.

Early safe patterns:

- constants;
- globals;
- direct calls;
- indirect calls;
- small ARM64 barrier/cache/TLB helpers;
- short ARM64 system-register read/write helpers;
- short straight-line diagnostic/logging sequences;
- one-statement `TPIDR_EL2` per-CPU read/callsites;
- small boot/init DAIF or EL handoff helpers.

Complex control flow, page-table walkers, locks, loops, mixed stores,
platform/device initialization, interrupt state machines, varargs internals,
and unclear dataflow stay `lifted-c` or semantic-label/body mismatch debt.

## Diagnostic summaries

When explicit diagnostic strings identify behavior but full dataflow is too
complex, S08 may apply a diagnostic-summary rewrite. This replaces an empty
wrapper with a short evidence-backed summary body and keeps full pseudocode in
evidence.

Diagnostic summaries improve readability, but they must not claim complete
source recovery of every branch or structure field. A trap or bounds check
without diagnostic strings/log calls is algorithmic evidence, not a
diagnostic-summary rewrite trigger.

## Naming-only passes

S08 may rename functions without promoting `output_class` when evidence strongly
identifies responsibility:

- evidence-backed names from S04/S07 sysregs, strings, MMIO, or callgraph;
- candidate-driven names for high-risk but clearly identified functions;
- simple-pseudocode names for strict one-statement constant returns or direct
  tail calls.

Broad anchors such as `TPIDR_EL2` alone are not sufficient for semantic naming.
They must be combined with stronger string, callgraph, module, or data-layout
evidence.

## Rehome, repair, and cleanup

After naming exposes a coherent family, S08 may rehome those functions into a
clearer source file. Rehome improves repository organization, not semantic
certainty: maps and source file lists must be updated, evidence must record the
move, and `output_class` remains unchanged.

Rehome must be followed by source-symbol readback. If any mapped symbol is
missing from source, S08 must restore a conservative wrapper from
`function-map.json`, record `source-symbol-repair-*` evidence, and rerun S09.
These repairs restore coverage only and must not be counted as semantic body
recovery.

If duplicate primary source-symbol definitions appear, S08 must remove only the
noncanonical copy whose file does not match `function-map.json`. Removed blocks
must be archived as evidence.

If S07 decompiler evidence exists for repair addresses, S08 should normalize
emergency repair wrappers into ordinary lifted source views. Normalization
removes the repair marker but does not promote source class, rename symbols, or
invent semantics.

## Presentation rules

S08 may:

- include review-seed object headers from S06 offset/global recovery;
- apply global presentation aliases from S06;
- annotate offset-family accesses as presentation aids;
- externalize inline Hex-Rays review blocks into S08 evidence.

Presentation passes must preserve uncertainty and original evidence. They do
not promote `output_class`.

When externalizing inline pseudocode review blocks, use function-definition
anchored cleanup only. Do not use broad cross-function regexes that search from
`#if 0` to the next `uintptr_t`; if an evidence comment sits between `#endif`
and a function definition, such regexes can swallow intervening functions.

After rewrite, naming, rehome, repair, or presentation passes, S08 must
synchronize source classes before S09. `function-map.json` is authoritative for
`output_class`, confidence, source file, and primary symbol.
