#!/usr/bin/env python3
"""Package workflow-v2 recovered source delivery.

The package keeps a clean source repository under deliverable/source and
places evidence/audit artifacts under deliverable/evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
FORBIDDEN_SOURCE_SUFFIXES = {".json", ".jsonl", ".sqlite", ".i64", ".idb"}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_file(src: Path, dst: Path) -> dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {"path": dst.as_posix(), "size": dst.stat().st_size, "sha256": sha256(dst)}


def copy_clean_source(src: Path, dst: Path) -> list[dict[str, Any]]:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("*.json", "*.jsonl", "*.sqlite", "*.i64", "*.idb", ".recovery"),
    )
    files = []
    forbidden = []
    for path in sorted(dst.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(dst).as_posix()
        if path.suffix.lower() in FORBIDDEN_SOURCE_SUFFIXES:
            forbidden.append(rel)
        files.append({"path": rel, "size": path.stat().st_size, "sha256": sha256(path)})
    if forbidden:
        raise RuntimeError(f"source payload contains forbidden artifacts: {forbidden}")
    if not any(f["path"].endswith(".c") for f in files) or not any(f["path"].endswith(".h") for f in files):
        raise RuntimeError("source payload must contain at least one .c and one .h file")
    return files


def package(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    s09 = case / "stages" / "S09"
    s10 = case / "stages" / "S10"
    delivery = read_json(s08 / "source-repo-delivery.json")
    source_audit = read_json(s09 / "source-repo-audit.json")
    static_audit = read_json(s09 / "static-audit-report.json")
    readability_audit_path = s09 / "readability-report.json"
    readability_audit = read_json(readability_audit_path) if readability_audit_path.exists() else None
    source_repo = ROOT / delivery["canonical_source_repo"]
    delivery_status = "blocked" if source_audit["status"] != "pass" else delivery.get("status", static_audit.get("status", "source_repo_ready"))
    if readability_audit and readability_audit.get("status") != "source_repo_ready":
        delivery_status = readability_audit["status"]

    deliverable = s10 / "deliverable"
    if deliverable.exists():
        shutil.rmtree(deliverable)
    source_payload = deliverable / "source" / "recovered-hypervisor"
    evidence_payload = deliverable / "evidence"

    source_files = copy_clean_source(source_repo, source_payload)
    evidence_specs = [
        (case / "stages" / "S06" / "type-candidates.json", evidence_payload / "S06" / "type-candidates.json"),
        (case / "stages" / "S06" / "struct-layouts.jsonl", evidence_payload / "S06" / "struct-layouts.jsonl"),
        (case / "stages" / "S06" / "global-object-model.json", evidence_payload / "S06" / "global-object-model.json"),
        (case / "stages" / "S06" / "argument-flow.jsonl", evidence_payload / "S06" / "argument-flow.jsonl"),
        (case / "stages" / "S06" / "ida-type-proposal.json", evidence_payload / "S06" / "ida-type-proposal.json"),
        (case / "stages" / "S06" / "offset-global-recovery-summary.json", evidence_payload / "S06" / "offset-global-recovery-summary.json"),
        (s08 / "source-repo-delivery.json", evidence_payload / "S08" / "source-repo-delivery.json"),
        (s08 / "function-map.json", evidence_payload / "S08" / "function-map.json"),
        (s08 / "source-map.json", evidence_payload / "S08" / "source-map.json"),
        (s08 / "source-quality-report.json", evidence_payload / "S08" / "source-quality-report.json"),
        (s08 / "unresolved-index.jsonl", evidence_payload / "S08" / "unresolved-index.jsonl"),
        (s08 / "source-class-sync-index.jsonl", evidence_payload / "S08" / "source-class-sync-index.jsonl"),
        (s08 / "source-class-sync-summary.json", evidence_payload / "S08" / "source-class-sync-summary.json"),
        (s08 / "source-symbol-repair-index.jsonl", evidence_payload / "S08" / "source-symbol-repair-index.jsonl"),
        (s08 / "source-symbol-repair-summary.json", evidence_payload / "S08" / "source-symbol-repair-summary.json"),
        (s08 / "source-symbol-repair-normalization-index.jsonl", evidence_payload / "S08" / "source-symbol-repair-normalization-index.jsonl"),
        (s08 / "source-symbol-repair-normalization-summary.json", evidence_payload / "S08" / "source-symbol-repair-normalization-summary.json"),
        (s08 / "duplicate-wrong-file-cleanup-index.jsonl", evidence_payload / "S08" / "duplicate-wrong-file-cleanup-index.jsonl"),
        (s08 / "duplicate-wrong-file-cleanup-summary.json", evidence_payload / "S08" / "duplicate-wrong-file-cleanup-summary.json"),
        (s08 / "duplicate-wrong-file-removed-blocks.jsonl", evidence_payload / "S08" / "duplicate-wrong-file-removed-blocks.jsonl"),
        (s08 / "semantic-rewrite-index.jsonl", evidence_payload / "S08" / "semantic-rewrite-index.jsonl"),
        (s08 / "semantic-rewrite-summary.json", evidence_payload / "S08" / "semantic-rewrite-summary.json"),
        (s08 / "arm64-arch-rewrite-index.jsonl", evidence_payload / "S08" / "arm64-arch-rewrite-index.jsonl"),
        (s08 / "arm64-arch-rewrite-summary.json", evidence_payload / "S08" / "arm64-arch-rewrite-summary.json"),
        (s08 / "percpu-rewrite-index.jsonl", evidence_payload / "S08" / "percpu-rewrite-index.jsonl"),
        (s08 / "percpu-rewrite-summary.json", evidence_payload / "S08" / "percpu-rewrite-summary.json"),
        (s08 / "boot-rewrite-index.jsonl", evidence_payload / "S08" / "boot-rewrite-index.jsonl"),
        (s08 / "boot-rewrite-summary.json", evidence_payload / "S08" / "boot-rewrite-summary.json"),
        (s08 / "sysreg-rewrite-index.jsonl", evidence_payload / "S08" / "sysreg-rewrite-index.jsonl"),
        (s08 / "sysreg-rewrite-summary.json", evidence_payload / "S08" / "sysreg-rewrite-summary.json"),
        (s08 / "log-sequence-rewrite-index.jsonl", evidence_payload / "S08" / "log-sequence-rewrite-index.jsonl"),
        (s08 / "log-sequence-rewrite-summary.json", evidence_payload / "S08" / "log-sequence-rewrite-summary.json"),
        (s08 / "diagnostic-summary-rewrite-index.jsonl", evidence_payload / "S08" / "diagnostic-summary-rewrite-index.jsonl"),
        (s08 / "diagnostic-summary-rewrite-summary.json", evidence_payload / "S08" / "diagnostic-summary-rewrite-summary.json"),
        (s08 / "diagnostic-summary-candidates.jsonl", evidence_payload / "S08" / "diagnostic-summary-candidates.jsonl"),
        (s08 / "diagnostic-summary-candidates-summary.json", evidence_payload / "S08" / "diagnostic-summary-candidates-summary.json"),
        (s08 / "rewrite-reconcile-summary.json", evidence_payload / "S08" / "rewrite-reconcile-summary.json"),
        (s08 / "semantic-name-index.jsonl", evidence_payload / "S08" / "semantic-name-index.jsonl"),
        (s08 / "semantic-name-summary.json", evidence_payload / "S08" / "semantic-name-summary.json"),
        (s08 / "evidence-semantic-name-index.jsonl", evidence_payload / "S08" / "evidence-semantic-name-index.jsonl"),
        (s08 / "evidence-semantic-name-summary.json", evidence_payload / "S08" / "evidence-semantic-name-summary.json"),
        (s08 / "candidate-semantic-name-index.jsonl", evidence_payload / "S08" / "candidate-semantic-name-index.jsonl"),
        (s08 / "candidate-semantic-name-summary.json", evidence_payload / "S08" / "candidate-semantic-name-summary.json"),
        (s08 / "simple-pseudocode-name-index.jsonl", evidence_payload / "S08" / "simple-pseudocode-name-index.jsonl"),
        (s08 / "simple-pseudocode-name-summary.json", evidence_payload / "S08" / "simple-pseudocode-name-summary.json"),
        (s08 / "module-rehome-index.jsonl", evidence_payload / "S08" / "module-rehome-index.jsonl"),
        (s08 / "module-rehome-summary.json", evidence_payload / "S08" / "module-rehome-summary.json"),
        (s08 / "evidence-semantic-name-rollback-summary.json", evidence_payload / "S08" / "evidence-semantic-name-rollback-summary.json"),
        (s08 / "evidence-semantic-name-broad-anchor-rollback-summary.json", evidence_payload / "S08" / "evidence-semantic-name-broad-anchor-rollback-summary.json"),
        (s08 / "global-alias-index.jsonl", evidence_payload / "S08" / "global-alias-index.jsonl"),
        (s08 / "global-alias-summary.json", evidence_payload / "S08" / "global-alias-summary.json"),
        (s08 / "offset-field-annotation-index.jsonl", evidence_payload / "S08" / "offset-field-annotation-index.jsonl"),
        (s08 / "offset-field-annotation-summary.json", evidence_payload / "S08" / "offset-field-annotation-summary.json"),
        (s08 / "lifted-pseudocode-review.jsonl", evidence_payload / "S08" / "lifted-pseudocode-review.jsonl"),
        (s08 / "lifted-pseudocode-review-summary.json", evidence_payload / "S08" / "lifted-pseudocode-review-summary.json"),
        (s08 / "source-view-cleanup-index.jsonl", evidence_payload / "S08" / "source-view-cleanup-index.jsonl"),
        (s08 / "source-view-cleanup-summary.json", evidence_payload / "S08" / "source-view-cleanup-summary.json"),
        (s09 / "source-repo-audit.json", evidence_payload / "S09" / "source-repo-audit.json"),
        (s09 / "readability-report.json", evidence_payload / "S09" / "readability-report.json"),
        (s09 / "readability-report.md", evidence_payload / "S09" / "readability-report.md"),
        (s09 / "semantic-rewrite-plan.json", evidence_payload / "S09" / "semantic-rewrite-plan.json"),
        (s09 / "semantic-rewrite-plan.md", evidence_payload / "S09" / "semantic-rewrite-plan.md"),
        (s09 / "consistency-report.json", evidence_payload / "S09" / "consistency-report.json"),
        (s09 / "static-audit-report.json", evidence_payload / "S09" / "static-audit-report.json"),
        (s09 / "static-audit-report.md", evidence_payload / "S09" / "static-audit-report.md"),
    ]
    evidence_files = []
    for src, dst in evidence_specs:
        if src.exists():
            copied = copy_file(src, dst)
            copied["path"] = dst.relative_to(deliverable).as_posix()
            evidence_files.append(copied)

    final_report = {
        "case_id": case_id,
        "stage_id": "S10",
        "iteration_id": "S10-V2-RW1",
        "generated_at": now_iso(),
        "workflow": "workflow-source-recovery-v2",
        "status": delivery_status,
        "canonical_source_repo": delivery["canonical_source_repo"],
        "delivered_source_path": "deliverable/source/recovered-hypervisor",
        "source_repo_audit_status": source_audit["status"],
        "static_audit_status": static_audit["status"],
        "readability_status": readability_audit["status"] if readability_audit else "not_run",
        "source_summary": {
            "file_count": len(source_files),
            "c_files": sum(1 for f in source_files if f["path"].endswith(".c")),
            "h_files": sum(1 for f in source_files if f["path"].endswith(".h")),
            "forbidden_intermediate_artifacts": 0,
        },
        "readability_ratios": readability_audit.get("ratios") if readability_audit else None,
        "readiness_blocker_count": len(readability_audit.get("readiness_blockers", [])) if readability_audit else None,
        "evidence_policy": "Evidence artifacts are packaged separately under deliverable/evidence and are not part of the source repository.",
    }
    if readability_audit:
        readability_lines = "\n".join(
            [
                f"- semantic-c ratio: `{readability_audit['ratios']['semantic_ratio']:.2%}`",
                f"- lifted-c ratio: `{readability_audit['ratios']['lifted_ratio']:.2%}`",
                f"- wrapper-body ratio: `{readability_audit['ratios']['wrapper_ratio']:.2%}`",
                f"- normal wrapper-body ratio: `{readability_audit['ratios'].get('normal_wrapper_ratio', 0):.2%}`",
                f"- source-symbol repair wrapper ratio: `{readability_audit['ratios'].get('source_symbol_repair_ratio', 0):.2%}`",
                f"- generic source-symbol ratio: `{readability_audit['ratios'].get('generic_source_symbol_ratio', 0):.2%}`",
                f"- IDA/address source-symbol ratio: `{readability_audit['ratios'].get('ida_source_symbol_ratio', 0):.2%}`",
                f"- inline pseudocode review-view ratio: `{readability_audit['ratios'].get('pseudocode_view_ratio', 0):.2%}`",
                f"- external pseudocode evidence ratio: `{readability_audit['ratios'].get('external_pseudocode_ratio', 0):.2%}`",
                f"- total pseudocode evidence ratio: `{readability_audit['ratios'].get('pseudocode_evidence_ratio', 0):.2%}`",
                f"- readiness blockers: `{len(readability_audit['readiness_blockers'])}`",
            ]
        )
    else:
        readability_lines = "Readability audit was not run."
    final_md = f"""# Final Recovery Delivery Report

Case: `{case_id}`

Status: `{final_report['status']}`

## Delivered source repository

`deliverable/source/recovered-hypervisor`

This directory is the source repository payload. It contains `.c` and `.h` files plus build-facing support files. It does not contain JSON/JSONL/IDA/SQLite intermediate artifacts.

## Source summary

- Files: `{final_report['source_summary']['file_count']}`
- `.c` files: `{final_report['source_summary']['c_files']}`
- `.h` files: `{final_report['source_summary']['h_files']}`
- Forbidden intermediate artifacts: `0`

## Evidence

Evidence and audit artifacts are packaged separately under:

`deliverable/evidence`

## Audit

- Source repository audit: `{source_audit['status']}`
- Static audit status: `{static_audit['status']}`
- Readability audit status: `{readability_audit['status'] if readability_audit else 'not_run'}`

## Readability

{readability_lines}

## Boundary

The source payload is a recovered, evidence-traceable corpus lift. It is not yet a source-repo-ready semantic reconstruction while readability blockers remain. The evidence workspace and JSON/JSONL artifacts are not the source repository.
"""

    write_json(s10 / "final-recovery-report.json", final_report)
    write_text(s10 / "final-recovery-report.md", final_md)
    write_text(deliverable / "README.md", final_md)
    copy_file(s10 / "final-recovery-report.json", deliverable / "reports" / "final-recovery-report.json")
    copy_file(s10 / "final-recovery-report.md", deliverable / "reports" / "final-recovery-report.md")

    packaged_files = []
    for path in sorted(deliverable.rglob("*")):
        if path.is_file():
            packaged_files.append(
                {
                    "path": path.relative_to(deliverable).as_posix(),
                    "size": path.stat().st_size,
                    "sha256": sha256(path),
                }
            )
    hashes = {"case_id": case_id, "stage_id": "S10", "files": packaged_files}
    manifest = {
        "case_id": case_id,
        "stage_id": "S10",
        "iteration_id": "S10-V2-RW1",
        "generated_at": now_iso(),
        "status": final_report["status"],
        "deliverable_root": str(deliverable.relative_to(ROOT)).replace("\\", "/"),
        "source_payload": "source/recovered-hypervisor",
        "evidence_payload": "evidence",
        "reports_payload": "reports",
        "source_files": source_files,
        "evidence_files": evidence_files,
        "packaged_file_count": len(packaged_files),
        "source_payload_policy": "No JSON/JSONL/IDA/SQLite artifacts are allowed inside source/recovered-hypervisor.",
    }
    validation = {
        "case_id": case_id,
        "stage_id": "S10",
        "iteration_id": "S10-V2-RW1",
        "result": "pass",
        "checks": [
            {
                "id": "S10-VAL-SOURCE-C",
                "result": "pass" if final_report["source_summary"]["c_files"] > 0 else "fail",
            },
            {
                "id": "S10-VAL-SOURCE-H",
                "result": "pass" if final_report["source_summary"]["h_files"] > 0 else "fail",
            },
            {
                "id": "S10-VAL-SOURCE-PURITY",
                "result": "pass",
            },
        ],
    }
    validation["result"] = "pass" if all(c["result"] == "pass" for c in validation["checks"]) else "fail"

    write_json(s10 / "artifact-hashes.json", hashes)
    write_json(s10 / "package-manifest.json", manifest)
    write_json(s10 / "artifact-validation-rw1.json", validation)
    write_json(
        s10 / "stage-manifest.json",
        {
            "case_id": case_id,
            "stage_id": "S10",
            "iteration_id": "S10-V2-RW1",
            "status": final_report["status"],
            "deliverable_root": manifest["deliverable_root"],
            "validation": validation["result"],
        },
    )
    return manifest


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    manifest = package(args.case_id)
    print(json.dumps({"case": args.case_id, "status": manifest["status"], "deliverable": manifest["deliverable_root"], "files": manifest["packaged_file_count"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
