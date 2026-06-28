---
name: integrate-el2-architecture-model
description: "Integrate S03 boot-flow, exception-model, context-layout, sysreg, and architecture-event outputs into a single ARM64 EL2 architecture model. Use to detect conflicts, produce S04-consumable architecture artifacts, and generate reviewed IDA rename/comment proposals for architecture-anchor functions (sysreg, boot, exception, MMU)."
---

# Integrate EL2 Architecture Model

## Purpose

Merge S03 worker outputs into one architecture model and produce IDA rename proposals for architecture-anchor functions. This Skill may directly read IDA through IDA MCP for verification without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S02/program-model.json`
- `S02/functions.jsonl` (with context frame data)
- `S02/call-graph.json`
- `S02/code-data-boundary-audit.json`
- `S02/unresolved-regions.jsonl`
- `S03/boot-model.json`
- `S03/exception-model.json`
- `S03/context-layouts.jsonl`
- `S03/sysreg-accesses.jsonl`
- `S03/architecture-events.jsonl`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce the S02 cleanliness gate.
   - Read S02 stage-manifest and unresolved-region files before merging S03 outputs.
   - If S02 is not `accepted`, set s04_readiness to `blocked_by_s02_rework`.
   - If S02 is `accepted` with `accepted-risk`, do not block S03/S04 solely for waived records.
   - Treat unresolved code/data/blob ranges as hard exclusions for architecture roots.

2. Verify inputs and connect to IDA read-only for verification.

3. Merge architecture roots.
   - Link boot roots, exception roots, context save/restore roots, and sysreg-anchored functions.
   - Do not integrate a function as architecture root if its boundary is marked false-start or merged without reviewed correction.

4. Resolve conflicts.
   - Boot vs exception root overlap.
   - Context offset width/type conflicts.
   - Sysreg semantics contradicting proposed function role.
   - Missing barrier/TLBI around page-table/TTBR changes.

5. Build S04-facing model.
   - `boot`
   - `exception`
   - `context_layout_refs`
   - `sysreg_index`
   - `architecture_event_index`
   - `candidate_runtime_anchors`
   - `blocking_unknowns`

6. Generate IDA rename proposal.
   - Propose `candidate_`-prefixed names for functions that match clear architecture-level mechanical patterns:

   **Boot (可以命名):**
   - Entry point → `candidate_boot_entry`
   - DAIFSet/DAIFClr instructions (interrupt mask toggle) → `candidate_disable_interrupts`
   - Consecutive MSR MAIR_EL2/TCR_EL2/SCTLR_EL2 (MMU setup) → `candidate_setup_mmu_el2`
   - MSR TTBR0_EL2 (page table base) → `candidate_set_ttbr0_el2`

   **Exception (可以命名):**
   - MSR VBAR_EL2 (vector table base) → `candidate_set_vbar_el2`
   - ERET instruction → `candidate_eret_exception_return`
   - SMC instruction at exception-handler root → `candidate_smc_handler`

   **System Register (可以命名):**
   - VTTBR_EL2 writers → `candidate_stage2_set_vttbr`
   - HCR_EL2 + VTTBR_EL2 + VTCR_EL2 together → `candidate_stage2_mmu_init` / `candidate_stage2_mmu_switch`
   - TLBI + DSB + ISB after TTBR change → `candidate_tlbi_invalidate`

   **Context (可以命名):**
   - Large-frame STP/LDP with TPIDR_EL2 → offset-first only: `candidate_context_save_sp120` (NOT `candidate_vcpu_save`)

   **禁止命名（留给 S04-S06）:**
   - Scheduler 相关（`do_schedule`, `runqueue` → S05）
   - VM/Domain lifecycle（`domain_create`, `domain_destroy` → S06）
   - vCPU 操作（`vcpu_run`, `vcpu_switch` → S04）
   - Interrupt routing（`irq_inject`, `vgic_update` → S05）
   - HKIP/security（`flask_check`, `avc_audit` → S06）

   - Keep names architecture-level only. Do not propose VM, scheduler, interrupt-route, lifecycle, or HKIP names.
   - All proposals use `candidate_` prefix; never `confirmed_` at S03.
   - Attach evidence IDs to each proposed rename.
   - Mark high-risk function boundary changes as review-only.

## Reusable Scripts

- `scripts/propose_architecture_names.py` — IDAPython: scans functions for architecture-level patterns (MSR/MRS to specific sysregs, ERET, TLBI sequences) and outputs a JSON rename proposal file ready for review.

## Outputs

Produce:

- `S03/architecture-model.json`
- `S03/ida-change-proposal.json` — Rename proposals for architecture-anchor functions with evidence IDs
- `S03/records/integrate-el2-architecture-model.evidence.jsonl`
- `S03/records/integrate-el2-architecture-model.decisions.jsonl`
- `S03/records/integrate-el2-architecture-model.unknowns.jsonl`

`architecture-model.json` should include:

- `architecture_roots` — Boot, exception, sysreg-anchored function addresses
- `boot_model_ref`
- `exception_model_ref`
- `context_layout_refs`
- `sysreg_access_refs`
- `architecture_event_refs`
- `runtime_anchor_candidates`
- `s04_readiness` — `ready` / `blocked_by_s02` / `ready_with_accepted_risks`
- `s02_gate` — S02 acceptance status for this model
- `rename_proposal_summary` — Count and categories of proposed renames
- `unresolved_dependencies`
- `rework_triggers`

`ida-change-proposal.json` should include:

- `renames`: `[{"address": "0x...", "current_name": "sub_...", "proposed_name": "candidate_...", "evidence_id": "S03-E...", "category": "boot|exception|sysreg|mmu", "confidence": "candidate"}]`

## Boundaries

- Do not apply IDA changes.
- Do not repair S02 boundaries silently; emit rework when S03 evidence invalidates S02.
- Do not assign VM config, scheduler, interrupt, lifecycle, or HKIP ownership.
- Do not upgrade candidate names to confirmed names without review.
- Do not use external symbols, source code, logs, DTB, traces, or non-IDA reverse tools.
