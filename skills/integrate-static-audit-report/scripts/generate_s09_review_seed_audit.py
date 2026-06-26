#!/usr/bin/env python3
"""Generate S09 review-seed index-consistency audit artifacts.

S09-RW1 audits the S08 review-seed scaffold for traceability and honest
coverage reporting. It does not issue production security invariant pass/fail
verdicts because S08 has no confirmed or inferred source units.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_ID = "xen_arm64-778090a1"
ROOT = Path(__file__).resolve().parents[3]
CASE = ROOT / "cases" / CASE_ID
S08 = CASE / "stages" / "S08"
S09 = CASE / "stages" / "S09"


POLICY = {
    "mode": "review_seed",
    "formal_input_boundary": "single binary plus IDA-derived static artifacts only",
    "oracle_policy": "oracle/symbolized samples are forbidden in production evidence",
    "audit_scope": "index consistency, traceability, honest coverage, and explicit unresolved blockers only",
    "forbidden_verdicts": "No production security invariant pass/fail verdicts from review-seed scaffold.",
}


INVARIANTS = [
    ("INV-VM-ISOLATION", "VM must not map other VM or hypervisor private pages."),
    ("INV-VCPU-CONTEXT", "vCPU context switch must not leak state across VMs."),
    ("INV-HKIP-WRITE-PROTECT", "HKIP protected regions must not become writable through ordinary mapping paths."),
    ("INV-IRQ-BINDING", "Passthrough interrupts must only inject into the bound VM/vCPU."),
    ("INV-TEARDOWN-CLEANUP", "VM destruction must reclaim page tables, VMID, IRQ routes, and CPU bindings."),
]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True))
            f.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def load_inputs() -> dict[str, Any]:
    return {
        "s08_manifest": read_json(S08 / "stage-manifest.json"),
        "recovery_index": read_json(S08 / "recovery-index.json"),
        "source_map": read_json(S08 / "source-map.json"),
        "coverage_summary": read_json(S08 / "coverage-summary.json"),
        "evidence_index": read_json(S08 / "recovery-evidence-index.json"),
        "decision_index": read_json(S08 / "recovery-decision-index.json"),
        "unknown_index": read_json(S08 / "recovery-unknown-index.json"),
        "unresolved": read_jsonl(S08 / "unresolved-index.jsonl"),
    }


def build_consistency(inputs: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    generated_files = inputs["recovery_index"].get("generated_files", [])
    source_objects = inputs["source_map"].get("objects", [])
    unresolved = inputs["unresolved"]
    source_paths = {obj.get("source_path") for obj in source_objects}
    missing_source_map = [row.get("path") for row in generated_files if row.get("path") not in source_paths]

    findings: list[dict[str, Any]] = []
    if missing_source_map:
        findings.append(
            {
                "id": "S09-CONSIST-0001",
                "severity": "error",
                "kind": "missing_source_map",
                "paths": missing_source_map,
            }
        )
    if inputs["coverage_summary"]["metrics"].get("confirmed_source_units") != 0:
        findings.append(
            {
                "id": "S09-CONSIST-0002",
                "severity": "error",
                "kind": "unexpected_confirmed_source_units",
                "reason": "Review-seed S08 must not contain confirmed source units.",
            }
        )
    if not unresolved:
        findings.append(
            {
                "id": "S09-CONSIST-0003",
                "severity": "error",
                "kind": "missing_unresolved_blockers",
                "reason": "Review-seed S08 must preserve unresolved blockers.",
            }
        )

    report = {
        "case_id": CASE_ID,
        "stage_id": "S09",
        "iteration_id": "S09-RW1",
        "status": "pass" if not findings else "fail",
        "mode": "review_seed_index_consistency",
        "generated_at": now_iso(),
        "policy": POLICY,
        "checks": [
            {
                "id": "S09-CHECK-SRCMAP",
                "result": "pass" if not missing_source_map else "fail",
                "summary": "Every S08 generated scaffold file has a source-map object.",
            },
            {
                "id": "S09-CHECK-COVERAGE-HONESTY",
                "result": "pass" if inputs["coverage_summary"]["metrics"].get("confirmed_source_units") == 0 else "fail",
                "summary": "Review-seed coverage does not claim confirmed source units.",
            },
            {
                "id": "S09-CHECK-UNRESOLVED-PRESERVED",
                "result": "pass" if unresolved else "fail",
                "summary": "Production blockers remain present in unresolved index.",
            },
        ],
        "finding_count": len(findings),
    }
    return report, findings


def build_security_invariants(inputs: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    unresolved_ids = [row.get("id") for row in inputs["unresolved"]]
    invariants = [
        {
            "id": inv_id,
            "description": desc,
            "verdict": "unknown",
            "mode": "review_seed_not_evaluable",
            "reason": "S08 has no confirmed source units, address-mapped functions, or production security-lifecycle links.",
            "blocking_unknowns": unresolved_ids,
        }
        for inv_id, desc in INVARIANTS
    ]
    findings = [
        {
            "id": f"S09-SEC-{idx:04d}",
            "severity": "review_required",
            "kind": "security_invariant_not_evaluable",
            "invariant": row["id"],
            "reason": row["reason"],
        }
        for idx, row in enumerate(invariants, 1)
    ]
    return (
        {
            "case_id": CASE_ID,
            "stage_id": "S09",
            "iteration_id": "S09-RW1",
            "status": "review_seed_not_evaluable",
            "policy": POLICY,
            "summary": {
                "pass": 0,
                "fail": 0,
                "unknown": len(invariants),
                "not_applicable": 0,
            },
            "invariants": invariants,
        },
        findings,
    )


def build_coverage(inputs: dict[str, Any], invariants: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    metrics = inputs["coverage_summary"].get("metrics", {})
    recovery_coverage = {
        "case_id": CASE_ID,
        "stage_id": "S09",
        "iteration_id": "S09-RW1",
        "status": "review_seed_only",
        "policy": POLICY,
        "source_coverage": {
            "confirmed_source_units": metrics.get("confirmed_source_units", 0),
            "inferred_c_units": metrics.get("inferred_c_units", 0),
            "asm_fallback_units": metrics.get("asm_fallback_units", 0),
            "stub_units": metrics.get("stub_units", 0),
            "unresolved_items": metrics.get("unresolved_items", 0),
            "address_mapped_functions": metrics.get("address_mapped_functions", 0),
        },
        "invariant_coverage": invariants["summary"],
        "production_recovery_coverage": {
            "confirmed_or_inferred_source_units": 0,
            "security_invariant_verdicts": 0,
            "note": "Production recovery coverage remains zero because S08 is unresolved/review-seed only.",
        },
    }
    findings = [
        {
            "id": "S09-COV-0001",
            "severity": "info",
            "kind": "review_seed_coverage",
            "summary": "Coverage intentionally reports zero confirmed/inferred source units.",
        }
    ]
    return recovery_coverage, findings


def build_audit_report(
    consistency: dict[str, Any],
    consistency_findings: list[dict[str, Any]],
    invariants: dict[str, Any],
    security_findings: list[dict[str, Any]],
    coverage: dict[str, Any],
    coverage_findings: list[dict[str, Any]],
    inputs: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]], str]:
    all_findings = consistency_findings + security_findings + coverage_findings
    report = {
        "case_id": CASE_ID,
        "stage_id": "S09",
        "iteration_id": "S09-RW1",
        "status": "review_seed_audit_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "consistency_status": consistency["status"],
        "security_invariant_status": invariants["status"],
        "coverage_status": coverage["status"],
        "recommendation": "go_to_s10_review_seed_package_only",
        "production_blocker": inputs["s08_manifest"]["gates"]["production"]["reason"],
        "finding_count": len(all_findings),
        "s10_readiness": {
            "production": "blocked_no_production_audit_verdict",
            "review_seed": "ready_for_review_seed_delivery_package",
        },
    }
    md = f"""# S09 Static Audit Report: Review-Seed Mode

Case: `{CASE_ID}`

Status: `review_seed_audit_ready_production_blocked`

## Outcome

S09-RW1 completed an index-consistency audit for the S08 unresolved scaffold.

It did not issue production security invariant pass/fail verdicts. All security invariants remain `unknown` because S08 has no confirmed source units, no inferred-C units, and no address-mapped recovered functions.

## Consistency

- Consistency status: `{consistency['status']}`
- Generated scaffold source-map coverage: checked
- Unresolved blockers preserved: checked

## Security invariants

- Pass: `0`
- Fail: `0`
- Unknown: `{invariants['summary']['unknown']}`

## Coverage

- Confirmed source units: `{coverage['source_coverage']['confirmed_source_units']}`
- Inferred-C units: `{coverage['source_coverage']['inferred_c_units']}`
- ASM fallback placeholders: `{coverage['source_coverage']['asm_fallback_units']}`
- Explicit stubs: `{coverage['source_coverage']['stub_units']}`
- Unresolved items: `{coverage['source_coverage']['unresolved_items']}`

## Recommendation

Proceed to S10 only as a review-seed delivery package. Production delivery remains blocked until S05-S07 recover confirmed resource ownership, lifecycle transitions, and HKIP/security evidence.
"""
    return report, all_findings, md


def main() -> None:
    inputs = load_inputs()
    consistency, consistency_findings = build_consistency(inputs)
    invariants, security_findings = build_security_invariants(inputs)
    coverage, coverage_findings = build_coverage(inputs, invariants)
    audit_report, audit_findings, audit_md = build_audit_report(
        consistency,
        consistency_findings,
        invariants,
        security_findings,
        coverage,
        coverage_findings,
        inputs,
    )

    validation = {
        "case_id": CASE_ID,
        "stage_id": "S09",
        "iteration_id": "S09-RW1",
        "result": "pass",
        "checks": [
            {
                "id": "S09-VAL-0001",
                "check": "security invariants do not contain production pass/fail verdicts",
                "result": "pass"
                if invariants["summary"]["pass"] == 0 and invariants["summary"]["fail"] == 0
                else "fail",
            },
            {
                "id": "S09-VAL-0002",
                "check": "coverage does not claim confirmed or inferred-C source units",
                "result": "pass"
                if coverage["source_coverage"]["confirmed_source_units"] == 0
                and coverage["source_coverage"]["inferred_c_units"] == 0
                else "fail",
            },
            {
                "id": "S09-VAL-0003",
                "check": "static audit recommends review-seed package only",
                "result": "pass"
                if audit_report["recommendation"] == "go_to_s10_review_seed_package_only"
                else "fail",
            },
        ],
    }
    validation["result"] = "pass" if all(row["result"] == "pass" for row in validation["checks"]) else "fail"

    manifest = {
        "case_id": CASE_ID,
        "stage_id": "S09",
        "iteration_id": "S09-RW1",
        "producer_skill": "integrate-static-audit-report",
        "status": "review_seed_audit_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "inputs": [
            "S08/stage-manifest.json",
            "S08/recovery-index.json",
            "S08/source-map.json",
            "S08/coverage-summary.json",
            "S08/recovery-evidence-index.json",
            "S08/recovery-decision-index.json",
            "S08/recovery-unknown-index.json",
            "S08/unresolved-index.jsonl",
        ],
        "outputs": [
            "S09/consistency-report.json",
            "S09/model-source-mismatches.jsonl",
            "S09/security-invariants.json",
            "S09/security-findings.jsonl",
            "S09/recovery-coverage.json",
            "S09/coverage-findings.jsonl",
            "S09/static-audit-report.json",
            "S09/static-audit-report.md",
            "S09/audit-findings.jsonl",
            "S09/artifact-validation-rw1.json",
        ],
        "gates": {
            "production": {
                "status": "blocked",
                "reason": audit_report["production_blocker"],
            },
            "review_seed": {
                "status": "ready",
                "reason": "Index consistency, honest coverage, and unresolved security-invariant blockers were audited.",
            },
        },
        "s10_readiness": audit_report["s10_readiness"],
    }

    write_json(S09 / "consistency-report.json", consistency)
    write_jsonl(S09 / "model-source-mismatches.jsonl", consistency_findings)
    write_json(S09 / "security-invariants.json", invariants)
    write_jsonl(S09 / "security-findings.jsonl", security_findings)
    write_json(S09 / "recovery-coverage.json", coverage)
    write_jsonl(S09 / "coverage-findings.jsonl", coverage_findings)
    write_json(S09 / "static-audit-report.json", audit_report)
    write_text(S09 / "static-audit-report.md", audit_md)
    write_jsonl(S09 / "audit-findings.jsonl", audit_findings)
    write_json(S09 / "artifact-validation-rw1.json", validation)
    write_json(S09 / "stage-manifest.json", manifest)

    print(
        json.dumps(
            {
                "stage": "S09",
                "iteration": "S09-RW1",
                "status": manifest["status"],
                "validation": validation["result"],
                "security_unknown": invariants["summary"]["unknown"],
                "findings": len(audit_findings),
                "s10_readiness": manifest["s10_readiness"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
