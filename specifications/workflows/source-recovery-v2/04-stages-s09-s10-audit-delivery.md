# Stages S09-S10: Audit and Delivery

## S09: Semantic consistency, security-invariant, and coverage audit

Goal: audit generated source against binary-derived evidence.

Checks:

- canonical source repository contains `.c`/`.h` files and no intermediate
  JSON/JSONL/IDA/SQLite artifacts;
- source-map entries read back to real symbols in the canonical source
  repository;
- each primary source symbol has exactly one canonical definition;
- source evidence comments identify the same image offset, output class, and
  confidence as `function-map.json`;
- corpus coverage metrics report IDA function count, generated source function
  count, output-class counts, and unresolved count;
- readability metrics report address-like symbol residue and IDA
  temporary/global-name residue where available;
- readability gate reports semantic-c ratio, lifted-c ratio, wrapper-body
  ratio, source-symbol repair ratio, and IDA residue score;
- pseudocode review coverage is reported separately as inline, external, and
  total evidence coverage;
- semantic-label/body mismatch is reported so `semantic-c` labels cannot hide
  generic wrapper implementations;
- CFG/call/constant/memory-access similarity where possible;
- sysreg/MMIO side effects preserved;
- structure offsets preserved;
- security invariants only when evidence supports verdicts;
- coverage separated by `lifted-c`, `semantic-c`, `asm-fallback`, and
  `unresolved`.

Exit condition: audit report distinguishes production conclusions from
unknowns.

## Readiness gates

`source_repo_ready` requires readability gates to pass. A corpus where most
functions are wrapper bodies, or where recovered logic exists only as a
non-compiling pseudocode review view, remains `source_corpus_lifted`.

S09 also produces a semantic rewrite plan that ranks files/modules by
readability debt. The next S08 rewrite batch should be selected from this plan
rather than by ad-hoc function picking.

S09 blocks `source_repo_ready` when primary source symbols are still dominated
by generated names such as:

- `runtime_helper_0001`;
- `cache_helper_0001`;
- `interrupt_helper_0001`;
- `timer_control_0001`;
- broad architecture placeholders such as `percpu_access_current_cpu_state_N`;
- IDA/address names such as `sub_1234` and `nullsub_7`.

## S10: Final report and delivery package

Goal: package source, evidence, reports, hashes, and reproduction notes.

Required package layout:

```text
S10/deliverable/
├── README.md
├── source/recovered-hypervisor/
├── evidence/
└── reports/
```

`source/recovered-hypervisor/` is the delivered source repository and must
remain free of JSON/JSONL/IDA/SQLite intermediate artifacts. Evidence and audit
JSON files belong under `evidence/`.

Exit condition: package status accurately reflects audit gates, hashes cover
packaged files, and the final report clearly distinguishes source payload from
evidence workspace. S10 must not promote `source_slice_ready` or
`source_corpus_lifted` to `source_repo_ready`.
