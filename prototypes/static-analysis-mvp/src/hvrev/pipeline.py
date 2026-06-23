# Prototype implementation; not a normative Workflow component.
from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

from . import __version__
from .aarch64 import (
    classify_functions,
    discover_functions,
    infer_bases,
    scan_architectural_events,
    scan_sysregs,
)
from .database import store_analysis
from .elf import build_synthetic_elf
from .image import build_manifest, parse_header, scan_artifacts
from .ida import build_action_plan
from .models import AnalysisResult
from .repository import create_repository
from .security import build_invariant_report


def _json_write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False), encoding="utf-8")


def ingest(image_path: Path, output: Path) -> tuple[bytes, dict]:
    data = image_path.read_bytes()
    header = parse_header(data)
    recovery = output / ".recovery"
    original = recovery / "original"
    original.mkdir(parents=True, exist_ok=True)
    immutable_copy = original / "Image"
    shutil.copyfile(image_path, immutable_copy)
    manifest = build_manifest(image_path, data, header)
    _json_write(recovery / "image-manifest.json", manifest)
    return data, manifest


def analyze(
    data: bytes, manifest: dict, explicit_base: int | None = None
) -> AnalysisResult:
    header = parse_header(data)
    artifacts = scan_artifacts(data, header)
    base_candidates = infer_bases(data, explicit_base)
    selected = base_candidates[0]
    entry_offset = 0
    base = selected.base
    sysregs = scan_sysregs(data, base)
    events = scan_architectural_events(data, base)
    functions = discover_functions(data, base, entry_offset)
    classify_functions(functions, sysregs)
    subsystem_counts = Counter(item.subsystem for item in functions)
    metrics = {
        "image_bytes": len(data),
        "header_magic_valid": header.valid_magic,
        "functions_discovered": len(functions),
        "sysreg_uses": len(sysregs),
        "architectural_events": len(events),
        "artifacts": len(artifacts),
        "subsystems": dict(sorted(subsystem_counts.items())),
        "selected_base_score": selected.score,
        "warning": (
            None
            if selected.score >= 10
            else "Load-base confidence is low; provide --base or confirm in IDA."
        ),
    }
    return AnalysisResult(
        base=base,
        entry=base + entry_offset,
        functions=functions,
        sysregs=sysregs,
        events=events,
        artifacts=artifacts,
        base_candidates=base_candidates,
        metrics=metrics,
    )


def write_analysis(output: Path, data: bytes, result: AnalysisResult) -> None:
    recovery = output / ".recovery"
    _json_write(recovery / "analysis.json", result.to_dict())
    _json_write(recovery / "function-map.json", [item.to_dict() for item in result.functions])
    _json_write(recovery / "address-map.json", {
        "selected_base": result.base,
        "selected_base_hex": f"0x{result.base:x}",
        "candidates": [item.to_dict() for item in result.base_candidates],
    })
    store_analysis(recovery / "analysis.sqlite", result, __version__)
    build_synthetic_elf(
        data,
        result.base,
        result.entry,
        result.functions,
        recovery / "synthetic-hypervisor.elf",
    )
    create_repository(output, result)
    build_action_plan(
        recovery / "analysis.json", recovery / "ida/proposed-actions.json"
    )
    _json_write(
        recovery / "reports/security-invariants.json",
        build_invariant_report(result),
    )
    _write_report(output, result)


def _write_report(output: Path, result: AnalysisResult) -> None:
    subsystem_lines = "\n".join(
        f"- `{name}`: {count}"
        for name, count in sorted(result.metrics["subsystems"].items())
    ) or "- No subsystem-classified functions yet"
    registers = Counter(item.register for item in result.sysregs)
    register_lines = "\n".join(
        f"- `{name}`: {count}" for name, count in registers.most_common()
    ) or "- No recognized EL2/GIC system-register accesses"
    events = Counter(item.detail for item in result.events)
    event_lines = "\n".join(
        f"- `{name}`: {count}" for name, count in events.most_common()
    ) or "- No recognized HVC/SMC/ERET/wait/barrier events"
    report = f"""\
# Initial recovery report

- Selected load base: `0x{result.base:x}`
- Base score: `{result.metrics['selected_base_score']}`
- Function candidates: `{len(result.functions)}`
- Recognized system-register uses: `{len(result.sysregs)}`
- Recognized architectural events: `{len(result.events)}`
- Embedded artifacts: `{len(result.artifacts)}`

## Function subsystem hints

{subsystem_lines}

## Architecture evidence

{register_lines}

## Control and synchronization events

{event_lines}

## Required human decisions

1. Confirm the load base and entry point in IDA.
2. Confirm exception vector candidates before creating handlers.
3. Review every `inferred-c` proposal before promoting it to `confirmed`.
4. Keep world-switch, exception-entry and atomic primitives as assembly when C
   recompilation cannot preserve their architectural behavior.
"""
    (output / ".recovery/reports/initial-analysis.md").write_text(report, encoding="utf-8")


def run_pipeline(image_path: Path, output: Path, base: int | None = None) -> AnalysisResult:
    output.mkdir(parents=True, exist_ok=True)
    data, manifest = ingest(image_path, output)
    result = analyze(data, manifest, base)
    write_analysis(output, data, result)
    return result
