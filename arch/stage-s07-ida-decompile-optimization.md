# S07: IDA Decompile Optimization Loop

S07 is the feedback loop that turns analysis evidence into better IDA decompiler output.

## Goal

Apply reviewed high-confidence names, comments, types, structs, arrays, and prototypes, then re-export decompiler evidence.

## Inputs

- S06 type and object proposals.
- IDA MCP read/write capability.
- Reviewed mutation policy.

## Outputs

- `ida-change-proposal.json`
- `ida-change-transactions.jsonl`
- `decompile-quality-report.json`
- `codegen-ready-functions.jsonl`

## Exit condition

Every selected function is routed to `codegen_ready`, `asm_fallback`, or `unresolved`.

## Boundary

Do not apply low-confidence type changes. Do not mutate bytes.

## Corpus-wide rule

S07 must emit `decompile-export-full.json` and `codegen-ready-functions.jsonl` for the complete function corpus. A small selected-target export is a slice artifact and cannot drive S08 full-repository status.

Every exported function is routed to one output class:

- `semantic-c`;
- `lifted-c`;
- `asm-fallback`;
- `unresolved`.
