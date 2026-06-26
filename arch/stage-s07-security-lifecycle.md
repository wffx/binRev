# S07: VM Lifecycle and HKIP Security Lifecycle

## Goal

S07 answers one question:

> Given the service-level evidence from S06, can we recover lifecycle transitions and hypervisor integrity protection relationships that are strong enough for repository synthesis and later security audit?

S07 does not invent VM lifecycle or HKIP semantics. If the upstream evidence only supports a static/per-CPU context sequence, S07 must preserve it as a review seed and explicitly block production recovery.

## Inputs

Production mode requires accepted S03-S06 artifacts:

```text
S06/service-model.json
S06/state-machines.jsonl
S05/resource-ownership.jsonl
S05/runtime-object-model.json
S05/stage2-memory-model.json
S04/architecture-events.jsonl
S04/sysreg-accesses.jsonl
S03/data-objects.jsonl
IDA read-only evidence when needed
```

Review-seed mode may consume:

```text
S05/runtime-object-model.json
S05/s05-rw18-convergence-gate.json
S06/stage-manifest.json
S06/service-model.json
S06/scheduler-model.json
S06/interrupt-model.json
S06/vm-config-model.json
S06/state-machines.jsonl
```

Oracle, symbolized binaries, debug builds, logs, DTB, and traces are not formal inputs. In lab validation they may be used only to improve workflow rules, never as production evidence.

## Skills

```text
recover-hypervisor-vm-lifecycle ----+
recover-hypervisor-hkip-model ------+--> integrate-hypervisor-security-lifecycle
```

The integration skill may read IDA through IDA MCP without asking for another connection confirmation, but it must not mutate IDA.

## Production workflow

1. Verify S06 production readiness.
2. Recover VM lifecycle anchors: create, load, start, pause, resume, reset, destroy, rollback, and cleanup.
3. Track resource transitions: VMID, pages, Stage-2 roots, IRQ routes, physical CPU/vCPU bindings, and context ownership.
4. Recover HKIP candidates: protected regions, permission toggles, write windows, integrity metadata, verification paths, and violation handlers.
5. Integrate lifecycle and HKIP into a security-lifecycle model.
6. Emit invariant inputs for S09, but do not perform S09 verdicts in S07.

## Review-seed workflow

If S06 is `review_seed_ready_production_blocked`, S07 switches to review-seed mode:

1. Carry forward S06 state machines only as `model_hypothesis`.
2. Do not label static/per-CPU context transitions as VM lifecycle transitions.
3. Emit resource-transition hypotheses only when they remain explicitly unowned.
4. Emit HKIP as `absent_or_unknown` unless protected objects and permission transitions are proven.
5. Keep production links empty.
6. Allow S08 only to build unresolved/review-seed repository scaffolding and evidence indexes.

## Outputs

```text
S07/
├── lifecycle-model.json
├── vm-lifecycle-model.json
├── hkip-model.json
├── resource-transitions.jsonl
├── state-transitions.jsonl
├── security-lifecycle-model.json
├── stage-manifest.json
├── artifact-validation-rw1.json
├── ida-change-proposal-rw1.json
└── records/
```

## Exit conditions

Production exit requires:

- confirmed or candidate VM lifecycle transitions tied to VM/vCPU/resource identity;
- resource transitions that name the affected VMID/page/IRQ/CPU-binding owner, or explicitly record unknowns;
- HKIP confirmed only with protected-object and permission-transition evidence;
- no unlabelled promotion from model hypothesis to confirmed fact.

Review-seed exit requires:

- all lifecycle/security claims are labelled `review_seed`, `model_hypothesis`, or `absent_or_unknown`;
- production links are empty;
- blocking unknowns explain what evidence is missing;
- downstream S08 readiness is limited to unresolved/review-seed scaffolding.

## Boundaries

- Do not perform final security invariant audit; S09 owns verdicts.
- Do not create lifecycle code from per-CPU/static context hypotheses.
- Do not treat ordinary read-only mappings or generic page-table permission code as HKIP.
- Do not use Oracle/symbolized samples as production evidence.
- Do not write IDA in S07 unless a separately reviewed mutation gate is added later.
