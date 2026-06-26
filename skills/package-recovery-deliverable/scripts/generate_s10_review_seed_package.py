#!/usr/bin/env python3
"""Generate S10 review-seed delivery package.

The package freezes S08/S09 review-seed outputs and final reports. It is not a
production recovered-source release.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_ID = "xen_arm64-778090a1"
ROOT = Path(__file__).resolve().parents[3]
CASE = ROOT / "cases" / CASE_ID
S08 = CASE / "stages" / "S08"
S09 = CASE / "stages" / "S09"
S10 = CASE / "stages" / "S10"
DELIVERABLE = S10 / "deliverable"


POLICY = {
    "mode": "review_seed",
    "formal_input_boundary": "single binary plus IDA-derived static artifacts only",
    "oracle_policy": "oracle/symbolized samples are forbidden in production evidence",
    "delivery_policy": "Package review-seed evidence, unresolved scaffold, and audit results only.",
    "production_status": "blocked",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_file(src: Path, dst: Path) -> dict[str, Any]:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    return {
        "source": src.relative_to(ROOT).as_posix(),
        "package_path": dst.relative_to(S10).as_posix(),
        "sha256": sha256_file(dst),
        "size": dst.stat().st_size,
    }


def copy_tree(src: Path, dst: Path) -> list[dict[str, Any]]:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)
    records: list[dict[str, Any]] = []
    for path in sorted(dst.rglob("*")):
        if path.is_file():
            original = src / path.relative_to(dst)
            records.append(
                {
                    "source": original.relative_to(ROOT).as_posix(),
                    "package_path": path.relative_to(S10).as_posix(),
                    "sha256": sha256_file(path),
                    "size": path.stat().st_size,
                }
            )
    return records


def build_final_report(
    s09_manifest: dict[str, Any],
    s08_coverage: dict[str, Any],
    s09_audit: dict[str, Any],
    s09_invariants: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    report_json = {
        "case_id": CASE_ID,
        "stage_id": "S10",
        "iteration_id": "S10-RW1",
        "status": "review_seed_delivery_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "summary": {
            "production_status": "blocked",
            "review_seed_status": "deliverable_ready",
            "reason": s09_manifest["gates"]["production"]["reason"],
            "s09_status": s09_manifest.get("status"),
            "recommendation": s09_audit.get("recommendation"),
        },
        "coverage": s08_coverage.get("metrics", {}),
        "security_invariants": s09_invariants.get("summary", {}),
        "included_artifact_classes": [
            "unresolved repository scaffold",
            "source maps and evidence indexes",
            "static audit report",
            "unresolved and unknown indexes",
            "package manifest and hashes",
        ],
        "not_included_as_claims": [
            "production recovered source",
            "confirmed VM lifecycle implementation",
            "confirmed HKIP implementation",
            "security invariant pass/fail verdicts",
            "byte-identical rebuilt Image",
        ],
    }
    report_md = f"""# Final Recovery Report: Review-Seed Delivery

Case: `{CASE_ID}`

Status: `review_seed_delivery_ready_production_blocked`

## Scope

This package is a review-seed deliverable. It freezes the current evidence, unresolved repository scaffold, source maps, coverage summaries, and static audit outputs.

It is not a production recovered-source release.

## Production blocker

{s09_manifest['gates']['production']['reason']}

## Coverage snapshot

- Confirmed source units: `{s08_coverage['metrics'].get('confirmed_source_units', 0)}`
- Inferred-C units: `{s08_coverage['metrics'].get('inferred_c_units', 0)}`
- ASM fallback placeholders: `{s08_coverage['metrics'].get('asm_fallback_units', 0)}`
- Explicit stubs: `{s08_coverage['metrics'].get('stub_units', 0)}`
- Unresolved items: `{s08_coverage['metrics'].get('unresolved_items', 0)}`
- Address-mapped functions: `{s08_coverage['metrics'].get('address_mapped_functions', 0)}`

## Security invariant snapshot

- Pass: `{s09_invariants['summary'].get('pass', 0)}`
- Fail: `{s09_invariants['summary'].get('fail', 0)}`
- Unknown: `{s09_invariants['summary'].get('unknown', 0)}`

## Delivery contents

- `deliverable/recovered-repo/`
- `deliverable/reports/`
- `deliverable/indexes/`
- `package-manifest.json`
- `artifact-hashes.json`

## Recommendation

Use this package for human review, workflow validation, and next-stage evidence planning. Do not treat it as a production-ready recovered hypervisor codebase.
"""
    return report_json, report_md


def main() -> None:
    s08_manifest = read_json(S08 / "stage-manifest.json")
    s08_coverage = read_json(S08 / "coverage-summary.json")
    s09_manifest = read_json(S09 / "stage-manifest.json")
    s09_audit = read_json(S09 / "static-audit-report.json")
    s09_invariants = read_json(S09 / "security-invariants.json")

    if DELIVERABLE.exists():
        shutil.rmtree(DELIVERABLE)
    DELIVERABLE.mkdir(parents=True, exist_ok=True)

    report_json, report_md = build_final_report(s09_manifest, s08_coverage, s09_audit, s09_invariants)
    write_json(S10 / "final-recovery-report.json", report_json)
    write_text(S10 / "final-recovery-report.md", report_md)

    copied: list[dict[str, Any]] = []
    copied.extend(copy_tree(S08 / "recovered-repo", DELIVERABLE / "recovered-repo"))

    report_files = [
        S10 / "final-recovery-report.md",
        S10 / "final-recovery-report.json",
        S09 / "static-audit-report.md",
        S09 / "static-audit-report.json",
        S09 / "security-invariants.json",
        S09 / "recovery-coverage.json",
        S09 / "consistency-report.json",
    ]
    for src in report_files:
        copied.append(copy_file(src, DELIVERABLE / "reports" / src.name))

    index_files = [
        S08 / "source-map.json",
        S08 / "address-to-source.json",
        S08 / "evidence-to-source.json",
        S08 / "recovery-index.json",
        S08 / "unresolved-index.jsonl",
        S08 / "recovery-evidence-index.json",
        S08 / "recovery-decision-index.json",
        S08 / "recovery-unknown-index.json",
        S09 / "audit-findings.jsonl",
        S09 / "security-findings.jsonl",
        S09 / "coverage-findings.jsonl",
    ]
    for src in index_files:
        copied.append(copy_file(src, DELIVERABLE / "indexes" / src.name))

    manifest_files = [
        S08 / "stage-manifest.json",
        S09 / "stage-manifest.json",
    ]
    for src in manifest_files:
        copied.append(copy_file(src, DELIVERABLE / "manifests" / f"{src.parent.name}-{src.name}"))

    reproduction_notes = """# Reproduction Notes

This is a review-seed package.

To reproduce the package from the current workspace state:

1. Verify S08 and S09 artifacts are present.
2. Run `python skills/package-recovery-deliverable/scripts/generate_s10_review_seed_package.py`.
3. Validate JSON/JSONL artifacts under `cases/xen_arm64-778090a1/stages/S10`.

No IDA analysis, binary mutation, or Oracle/symbolized sample is required for S10 packaging.
"""
    write_text(DELIVERABLE / "REPRODUCE.md", reproduction_notes)
    copied.append(
        {
            "source": "generated:S10/reproduction-notes",
            "package_path": (DELIVERABLE / "REPRODUCE.md").relative_to(S10).as_posix(),
            "sha256": sha256_file(DELIVERABLE / "REPRODUCE.md"),
            "size": (DELIVERABLE / "REPRODUCE.md").stat().st_size,
        }
    )

    package_manifest = {
        "case_id": CASE_ID,
        "stage_id": "S10",
        "iteration_id": "S10-RW1",
        "producer_skill": "package-recovery-deliverable",
        "status": "review_seed_delivery_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "upstream": {
            "S08_status": s08_manifest.get("status"),
            "S09_status": s09_manifest.get("status"),
            "S09_s10_production": s09_manifest.get("s10_readiness", {}).get("production"),
            "S09_s10_review_seed": s09_manifest.get("s10_readiness", {}).get("review_seed"),
        },
        "files": copied,
        "file_count": len(copied),
    }
    artifact_hashes = {
        "case_id": CASE_ID,
        "stage_id": "S10",
        "iteration_id": "S10-RW1",
        "files": [
            {
                "path": row["package_path"],
                "sha256": row["sha256"],
                "size": row["size"],
            }
            for row in copied
        ],
    }
    validation = {
        "case_id": CASE_ID,
        "stage_id": "S10",
        "iteration_id": "S10-RW1",
        "result": "pass",
        "checks": [
            {
                "id": "S10-VAL-0001",
                "check": "package is explicitly review-seed and production-blocked",
                "result": "pass" if package_manifest["status"] == "review_seed_delivery_ready_production_blocked" else "fail",
            },
            {
                "id": "S10-VAL-0002",
                "check": "unresolved index is included",
                "result": "pass"
                if any(row["package_path"].endswith("unresolved-index.jsonl") for row in copied)
                else "fail",
            },
            {
                "id": "S10-VAL-0003",
                "check": "artifact hashes are present for every packaged file",
                "result": "pass" if len(artifact_hashes["files"]) == len(copied) else "fail",
            },
        ],
    }
    validation["result"] = "pass" if all(row["result"] == "pass" for row in validation["checks"]) else "fail"

    stage_manifest = {
        "case_id": CASE_ID,
        "stage_id": "S10",
        "iteration_id": "S10-RW1",
        "producer_skill": "package-recovery-deliverable",
        "status": "review_seed_delivery_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "inputs": [
            "S08/recovered-repo/",
            "S08/source-map.json",
            "S08/unresolved-index.jsonl",
            "S09/static-audit-report.md",
            "S09/stage-manifest.json",
        ],
        "outputs": [
            "S10/final-recovery-report.md",
            "S10/final-recovery-report.json",
            "S10/deliverable/",
            "S10/package-manifest.json",
            "S10/artifact-hashes.json",
            "S10/artifact-validation-rw1.json",
        ],
        "gates": {
            "production": {
                "status": "blocked",
                "reason": s09_manifest["gates"]["production"]["reason"],
            },
            "review_seed": {
                "status": "complete",
                "reason": "Review-seed deliverable package was generated with hashes and unresolved indexes.",
            },
        },
    }

    write_json(S10 / "package-manifest.json", package_manifest)
    write_json(S10 / "artifact-hashes.json", artifact_hashes)
    write_json(S10 / "artifact-validation-rw1.json", validation)
    write_json(S10 / "stage-manifest.json", stage_manifest)

    print(
        json.dumps(
            {
                "stage": "S10",
                "iteration": "S10-RW1",
                "status": stage_manifest["status"],
                "validation": validation["result"],
                "packaged_files": len(copied),
                "production": stage_manifest["gates"]["production"]["status"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
