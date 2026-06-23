# Static Analysis MVP Prototype

This directory contains the early Python and IDAPython prototype created before
the AI Native Workflow contracts were finalized.

It is not the product architecture and is not a normative implementation of any
Stage or Skill. Code here may later be extracted into individual Skills only
after its inputs, outputs and evidence behavior conform to the contracts under
`../../specifications/`.

## Current capabilities

- Parse an ARM64 boot executable `Image`.
- Generate load-address and function candidates.
- Scan selected EL2/GIC system-register operations.
- Create a synthetic ELF and SQLite evidence database.
- Export and apply limited IDA state transactions through IDAPython.

## Run the prototype

From this directory:

```powershell
python -m pip install -e .
hvrev pipeline .\Image -o .\recovered-hypervisor
```

Run tests:

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

Prototype output does not satisfy the final Artifact Contract unless separately
validated and adapted.
