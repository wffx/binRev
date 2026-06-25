---
name: recover-el2-architecture-semantics
description: "Recover S04 ARM64 EL2 architecture semantics from IDA evidence. Use to index MRS/MSR system-register accesses, HVC/SMC/ERET, TLBI/cache/barrier instructions, timer/GIC/SMMU-like architecture events, and their data/control dependencies without assigning high-level business modules."
---

# Recover EL2 Architecture Semantics

## Purpose

Create an architecture-event index grounded in target instructions. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It does not mutate IDA.

## Inputs

Require:

- `S03/stage-manifest.json`
- `S03/program-model.json`
- `S03/functions.jsonl`
- `S03/call-graph.json`
- `S03/unresolved-regions.jsonl`
- `S03/unresolved-regions*.jsonl` when rework iterations exist
- `S04/boot-model.json` when available
- `S04/exception-model.json` when available
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Run the S03 gate preflight.
   - Read `S03/stage-manifest.json` and all available unresolved-region files.
   - If S03 is not `accepted` or contains blocking unresolved code/data/blob ranges, run only in `forward_test_deferred_by_s03_rework` mode.
   - Architecture events may still be indexed in forward-test mode, but every event overlapping or depending on an unresolved blob must carry `blocked_by_s03_unresolved_blob`.
   - Do not promote sysreg-heavy unowned code inside unresolved blobs into architecture roots.

2. Connect to IDA read-only and record transport metadata.

3. Index system-register accesses.
   - Record `MRS`/`MSR` sites, target sysreg, source/destination GPR, containing function, and nearby constants.
   - Prioritize EL2 registers: `HCR_EL2`, `SCTLR_EL2`, `TCR_EL2`, `MAIR_EL2`, `TTBR0_EL2`, `VTCR_EL2`, `VTTBR_EL2`, `VBAR_EL2`, `ESR_EL2`, `FAR_EL2`, `HPFAR_EL2`, `ELR_EL2`, `SPSR_EL2`, `CNTHCTL_EL2`, `TPIDR_EL2`.
   - Keep unknown encoded sysregs as raw operands when IDA cannot decode them.

4. Index architecture events.
   - `HVC`, `SMC`, `ERET`.
   - `TLBI`, `IC`, `DC`.
   - `DMB`, `DSB`, `ISB`.
   - `WFI`, `WFE`, `SEV`.
   - GIC/ICH/ICC-like sysregs and MMIO-like accesses only as architecture candidates.

5. Recover local dependencies.
   - Track immediate construction and simple dataflow into sysreg writes.
   - Link barriers/cache/TLBI to nearby page-table or TTBR updates.
   - Link exception sysreg reads to handler/dispatch paths.

6. Emit semantics conservatively.
   - Architecture action may be confirmed; business role remains candidate.
   - Example: `MSR VTTBR_EL2` confirms a Stage-2 root switch event, not a VM lifecycle function.
   - Emit `s03_gate_status`, `unresolved_dependencies`, and `production_eligible: false` when S03 is not accepted.

## Outputs

Produce:

- `S04/sysreg-accesses.jsonl`
- `S04/architecture-events.jsonl`
- `S04/records/recover-el2-architecture-semantics.evidence.jsonl`
- `S04/records/recover-el2-architecture-semantics.decisions.jsonl`
- `S04/records/recover-el2-architecture-semantics.unknowns.jsonl`

Architecture-event records should include:

- `event_id`
- `address`
- `function_id`
- `instruction`
- `event_kind`
- `register_or_operation`
- `operands`
- `local_dependency`
- `candidate_semantic`
- `confidence`
- `s03_gate_status`
- `unresolved_dependencies`
- `production_eligible`

## Boundaries

- Do not infer VM config, scheduler, lifecycle, HKIP, or interrupt route solely from a sysreg.
- Do not use architecture specs as target-specific evidence; use them only to decode instruction semantics.
- Do not apply IDA writes directly.
- Do not use external symbols, source, logs, DTB, dynamic trace, or non-IDA reverse tools.
