# Workflow v2 Overview and Policy

## Purpose

This workflow is optimized for the real goal:

> Input one unsigned ARM64 hypervisor-like binary and produce a source
> repository whose code is driven by IDA/assembly evidence, not by empty module
> stubs.

The workflow keeps evidence governance and auditability, but source recovery is
centered on function-level lifting and incremental semantic improvement.

## Formal inputs

- one target binary;
- optional IDA database derived from the same target binary;
- IDA and IDA MCP access.

## Validation-only inputs

- symbolized/oracle binaries;
- debug builds;
- external logs or traces.

Validation-only inputs may be used to score and improve the workflow in lab
runs. They are not production inputs and must not appear in production evidence
chains, source-map claims, or final source comments.

## Core policy changes from v1

1. Do not generate `.c` / `.h` files for unresolved modules.
2. Corpus-wide mode must route every exported IDA function to `semantic-c`,
   `lifted-c`, `asm-fallback`, or `unresolved`.
3. Keep `lifted-c` and `semantic-c` separate.
4. Use IDA decompile/type feedback as a first-class stage, not a side effect.
5. Treat business/module names as hypotheses until backed by control flow,
   dataflow, xrefs, sysregs, strings, structure offsets, or other binary
   evidence.

## Source repository definition

The canonical source repository is:

```text
recovered-repos/<case-id>/recovered-hypervisor/
```

The case stage directory is an evidence workspace:

```text
cases/<case-id>/stages/
```

Do not call the evidence workspace a source repository. S10 packages source and
evidence separately.
