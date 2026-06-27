# Source-Recovery Workflow v2 Split Index

This directory contains the maintainable split form of
`specifications/workflow-source-recovery-v2.md`.

## Documents

1. [00-overview-and-policy.md](00-overview-and-policy.md)
2. [01-stages-s00-s03.md](01-stages-s00-s03.md)
3. [02-stages-s04-s07.md](02-stages-s04-s07.md)
4. [03-stage-s08-source-repository.md](03-stage-s08-source-repository.md)
5. [04-stages-s09-s10-audit-delivery.md](04-stages-s09-s10-audit-delivery.md)
6. [05-function-codegen-gate.md](05-function-codegen-gate.md)

## Maintenance guidance

- Update the narrowest stage document first.
- Keep the root workflow file as a stable entry point for skills and other docs.
- Put cross-stage invariants in the root file only when at least two stage
  documents depend on them.
- Do not duplicate large stage contracts across files; link to the owning
  document instead.
