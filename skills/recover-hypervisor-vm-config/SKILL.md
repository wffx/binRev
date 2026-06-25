---
name: recover-hypervisor-vm-config
description: "Recover S06 VM configuration candidates from accepted S03-S05 hypervisor runtime evidence. Use when the workflow needs static VM/vCPU/memory/device/IRQ configuration objects embedded in the Image, without assuming external DTB, logs, or config files."
---

# Recover Hypervisor VM Config

## Purpose

Recover embedded VM configuration candidates and their links to runtime objects. This Skill may directly read IDA through IDA MCP without asking for a separate connection confirmation. It must not mutate IDA.

## Inputs

Require:

- `S05/runtime-object-model.json`
- `S05/types.jsonl`
- `S05/resource-ownership.jsonl`
- `S05/cpu-vcpu-model.json`
- `S05/stage2-memory-model.json`
- `S03/program-model.json`
- `S04/architecture-model.json`
- accepted IDA checkpoint or IDA MCP session

## Workflow

1. Enforce upstream gates.
   - Require accepted S03, S04, and S05.
   - If upstream is not accepted, emit `blocked_by_upstream` only.

2. Locate configuration-like data.
   - Search fixed arrays, pointer tables, initializer paths, validation functions, and string-linked records.
   - Track VM, vCPU count, memory region, device, IRQ, and capability-like fields as candidates.

3. Link config to runtime objects.
   - Connect config records to CPU/vCPU/context/VMID/stage2/page ownership only when xrefs and writes support it.
   - Keep field names generic until S06 integration.

4. Preserve uncertainty.
   - Mark absent external config explicitly.
   - Do not invent VM definitions when only business background suggests them.

## Outputs

Produce:

- `S06/vm-config-model.json`
- `S06/records/recover-hypervisor-vm-config.evidence.jsonl`
- `S06/records/recover-hypervisor-vm-config.decisions.jsonl`
- `S06/records/recover-hypervisor-vm-config.unknowns.jsonl`

## Boundaries

- Do not recover scheduler policy, interrupt routing behavior, lifecycle, or HKIP.
- Do not assume DTB, boot logs, or external config exists.
- Do not apply IDA writes directly.
