# Stages S00-S03: Input, Image, IDA, and Boundaries

## S00: Case initialization and constraint lock

Goal: create a case identity and freeze the allowed inputs.

Formal inputs:

- one target binary;
- optional IDA database derived from the target binary;
- IDA MCP access.

Validation-only inputs:

- symbolized/oracle binaries;
- debug builds;
- external logs/traces.

Outputs:

- case manifest;
- input boundary policy;
- Oracle-use policy.

Exit condition: every artifact can distinguish production evidence from
validation-only evidence.

## S01: Binary/Image layout and load-address recovery

Goal: recover file layout, candidate load addresses, segments, embedded data,
and synthetic ELF metadata.

Outputs:

- image manifest;
- address-map;
- segment map;
- load-address candidates.

Exit condition: IDA and later stages can consistently map file offsets to
virtual addresses.

## S02: IDA database preparation and capability handshake

Goal: establish IDA as the authoritative analysis state.

Outputs:

- IDA snapshot;
- MCP capability report;
- read/write capability flags;
- transaction policy.

Exit condition: IDA reads are reliable; writes require reviewed proposals or
high-confidence workflow-approved automation.

## S03: Code/data/function boundary recovery

Goal: recover executable boundaries before semantic interpretation.

Required work:

- resolve text/data/code islands;
- create or propose missing functions;
- remove false function starts;
- recover branch targets and veneers;
- keep unresolved bytes out of the middle of executable text unless explicitly
  classified;
- repair wrong IDA tail-chunk ownership when candidate entries are attached to
  unrelated functions;
- split shared suffix/local-entry functions only after target-only control-flow
  and side-effect evidence supports an independent entry.

Outputs:

- `functions.jsonl`;
- `data-objects.jsonl`;
- call graph;
- boundary proposals;
- unresolved boundary index.

Exit condition: high-value text ranges have code/data classification good
enough for decompilation.

Readback rule: an applied boundary repair is successful only when the repaired
candidate reads back as an exact IDA function root and the owning chunks no
longer point to an unrelated function. If Hex-Rays output is available only for
a containing function, the candidate remains `boundary_mismatch`.
