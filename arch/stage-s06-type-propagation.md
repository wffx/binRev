# S06: Type, Structure, Global Object, and Argument Propagation

S06 improves decompiler quality by recovering types and data shapes.

## Goal

Recover enough type context for selected function clusters to be lifted into readable source.

## Inputs

- S05 clusters.
- IDA decompiler output.
- xrefs, globals, strings, sysregs, and structure offset families.

## Outputs

- `type-candidates.json`
- `struct-layouts.jsonl`
- `global-object-model.json`
- `argument-flow.jsonl`
- `ida-type-proposal.json`

## Exit condition

Each selected function is classified as type-improved, type-partial, asm-fallback, or unresolved.

## Boundary

Do not force a structure name or field name without evidence. Do not use Oracle names as production evidence.

## Corpus-wide rule

S06 must emit name candidates for every clustered function, not only selected high-confidence functions.

Primary symbol names should not be raw addresses. When semantic evidence is weak, use stable module-local names such as `mmu_helper_0001` and retain IDA address/name only in comments and source maps.

S06 must recover corpus-wide offset/global review seeds before source readiness can improve:

- repeated argument-base offset families such as `a1 + 0x18`;
- access width and hit/function counts for each candidate field;
- high-frequency `qword_*`, `dword_*`, `byte_*` global references;
- module/source-file neighborhoods for globals and offset families;
- candidate structs whose field names preserve offsets until stronger evidence exists.

Generated candidate headers are allowed only as review seeds. They must use comments/raw storage or otherwise avoid pretending that overlapping offsets are confirmed C layouts.

Every function should receive one type-context class:

- `semantic`;
- `partial`;
- `generic-context`;
- `asm-fallback`;
- `unresolved`.

Additional v2 outputs:

- `offset-global-recovery-summary.json`;
- enhanced `struct-layouts.jsonl`;
- enhanced `global-object-model.json`;
- enhanced `argument-flow.jsonl`;
- optional `include/recovered/recovered_objects.h` in the source repository.
