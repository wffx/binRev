---
name: orchestrate-hypervisor-recovery
description: "Orchestrate the full AI-native ARM64 hypervisor Image recovery workflow across S00-S10. Use to route stages, enforce gates, choose producer skills, propagate unknowns, prevent forward-test artifacts from becoming production evidence, and decide when to stop for review."
---

# Orchestrate Hypervisor Recovery

## Purpose

Coordinate the stage workflow without doing producer analysis itself. This Skill owns sequencing, gate enforcement, artifact routing, and status transitions.

## Inputs

Require:

- current case directory
- stage manifests
- workflow/specification documents
- user-approved scope and tool boundary

## Workflow

1. Read current stage manifests.
2. Select the next runnable stage.
   - Run a stage only when required upstream inputs are accepted.
   - Allow forward-test only when explicitly marked and isolated from production evidence.
3. Route producer skills.
   - Use worker skills first, then integration, review, IDA apply where allowed, snapshot, and validation.
4. Enforce gates.
   - Stop at review, rework, or blocked states.
   - Do not bypass blocking unresolved items.
5. Maintain consistency.
   - Ensure every artifact has evidence/decision/unknown records.
   - Propagate stale status when upstream IDA or model state changes.

## Outputs

Produce or update:

- stage status updates
- next-action recommendation
- orchestration records
- stale/rework/block notes

## Boundaries

- Do not infer binary semantics directly.
- Do not write IDA directly.
- Do not promote oracle or forward-test evidence into production artifacts.
