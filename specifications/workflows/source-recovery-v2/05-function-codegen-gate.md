# Function-Level Codegen Gate

Only functions with `output_class` equal to `lifted-c`, `semantic-c`, or
`asm-fallback` may create source files. `unresolved` records must not create
fake internal source.

Example gate record:

```json
{
  "function": "0x5c4",
  "boundary": "accepted",
  "decompile": "available",
  "architecture_side_effects": ["TTBR0_EL2", "SCTLR_EL2", "TLBI ALLE2"],
  "globals": ["dword_7C0"],
  "cluster": "boot_mmu",
  "type_context": "partial",
  "output_class": "lifted-c",
  "confidence": "high"
}
```

## Boundary mismatch rule

If the target address is a suspected function root but IDA only provides a
containing function whose start address differs, the candidate is not
`codegen_ready`.

Record it as `boundary_mismatch` and send it back to S03/S07 for boundary
repair instead of lifting the containing function into source.

## Source-map rule

Every generated source function must have:

- target address;
- original IDA name;
- primary source symbol;
- source file path;
- output class;
- confidence;
- evidence provenance.

Addresses and IDA names may appear in comments and source maps. They must not
dominate primary source symbols in a repository that claims `source_repo_ready`.
