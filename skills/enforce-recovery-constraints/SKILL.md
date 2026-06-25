---
name: enforce-recovery-constraints
description: "Generate and enforce the machine-readable constraint profile for one ARM64 EL2 Hypervisor Image recovery case. Use in S00 after case initialization to lock allowed inputs, allowed IDA/IDA-MCP usage, forbidden evidence, forbidden claims, and acceptance boundaries."
---

# Enforce Recovery Constraints

## Purpose

Turn the project boundary into a machine-readable contract that downstream Skills must obey. This Skill prevents scope creep before any reverse engineering starts.

## Inputs

Require:

- `S00/case-manifest.json`
- `case-request.json`
- `specifications/contracts/constraint-boundary.md`
- `specifications/contracts/ida-tool-contract.md`

## Workflow

1. Lock input boundary.
   - Allow exactly the single binary recorded in `case-manifest.json`.
   - Treat IDB files as analysis state, not as additional binary samples.
   - Treat business background as hypothesis, not binary evidence.

2. Lock tool boundary.
   - Allow IDA, IDAPython, and IDA MCP only as an automation/transport layer for IDA.
   - Allow Hex-Rays only if present in the local IDA installation.
   - Forbid external reverse-engineering tools, runtime execution, debuggers, emulators, external symbol packs, source trees, logs, DTBs, and platform documents.

3. Lock claim boundary.
   - Permit candidate, inferred, confirmed, unknown, absent, and blocked confidence states.
   - Forbid claims of original source recovery, runtime equivalence, complete buildability, exploitability proof, or security proof.
   - Require each technical claim to cite evidence from the binary, accepted artifacts, or accepted IDA state.

4. Lock mutation boundary.
   - S00-S01 do not use IDA.
   - S02-S07 may propose IDA changes; only `apply-reviewed-ida-changes` may commit reviewed changes.
   - S08-S10 are read-only with respect to IDA.

## Outputs

Produce:

- `S00/constraint-profile.json`
- `S00/records/enforce-recovery-constraints.evidence.jsonl`
- `S00/records/enforce-recovery-constraints.decisions.jsonl`
- `S00/records/enforce-recovery-constraints.unknowns.jsonl`

`constraint-profile.json` should include:

- `allowed_inputs`
- `allowed_tools`
- `allowed_knowledge`
- `forbidden_inputs`
- `forbidden_tools`
- `forbidden_claims`
- `ida_mutation_policy`
- `confidence_policy`
- `human_gate_policy`

## Boundaries

- Do not inspect implementation details.
- Do not weaken constraints to fit a convenient tool or sample.
- Do not mark user background as evidence.
- Do not authorize an additional binary, external source base, or dynamic environment.
