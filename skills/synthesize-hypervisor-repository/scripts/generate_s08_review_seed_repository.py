#!/usr/bin/env python3
"""Generate S08 unresolved/review-seed repository scaffold.

This script consumes S07 review-seed artifacts and creates a traceable
repository seed. It does not synthesize confirmed lifecycle, HKIP, scheduler,
interrupt, VM, vCPU, or Stage-2 logic from model hypotheses.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CASE_ID = "xen_arm64-778090a1"
ROOT = Path(__file__).resolve().parents[3]
CASE = ROOT / "cases" / CASE_ID
S07 = CASE / "stages" / "S07"
S08 = CASE / "stages" / "S08"
REPO = S08 / "recovered-repo"


POLICY = {
    "mode": "review_seed",
    "formal_input_boundary": "single binary plus IDA-derived static artifacts only",
    "oracle_policy": "oracle/symbolized samples are forbidden in production evidence",
    "source_synthesis_policy": "Do not generate confirmed source semantics from model_hypothesis records.",
    "allowed_output": "unresolved repository scaffold, evidence indexes, explicit failing stubs, and review queues.",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


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


def rel(path: Path) -> str:
    return path.relative_to(S08).as_posix()


def build_repo_files() -> list[dict[str, Any]]:
    files: list[tuple[str, str, str]] = [
        (
            "README.md",
            """# Recovered Hypervisor Repository Seed

This repository is an S08 review-seed scaffold. It is traceable, but it is not a confirmed source recovery.

Production lifecycle, HKIP, scheduler, VM, vCPU, Stage-2, and interrupt semantics are blocked upstream. Files under this scaffold are intentionally unresolved or explicit failing stubs.
""",
            "repository overview",
        ),
        (
            "include/recovered/status.h",
            """#pragma once

enum recovered_status {
    RECOVERED_UNRESOLVED = -1,
    RECOVERED_NOT_IMPLEMENTED = -2,
    RECOVERED_REVIEW_SEED_ONLY = -3,
};
""",
            "shared unresolved status definitions",
        ),
        (
            "core/lifecycle/lifecycle_unresolved.c",
            """#include <recovered/status.h>

int recovered_vm_lifecycle_unresolved(void)
{
    return RECOVERED_REVIEW_SEED_ONLY;
}
""",
            "explicit failing lifecycle stub",
        ),
        (
            "security/hkip/hkip_unresolved.c",
            """#include <recovered/status.h>

int recovered_hkip_unresolved(void)
{
    return RECOVERED_REVIEW_SEED_ONLY;
}
""",
            "explicit failing HKIP stub",
        ),
        (
            "recovered/asm_fallback/s07_review_seed.S",
            """.section .text
/* S07 review-seed placeholder.
 * No confirmed world-switch, lifecycle, or HKIP assembly is recovered in S08-RW1.
 */
""",
            "assembly fallback placeholder",
        ),
        (
            ".recovery/README.md",
            """# Recovery Metadata

Machine-readable indexes for this review-seed repository live next to this scaffold in the S08 stage directory.
""",
            "metadata notice",
        ),
    ]

    generated = []
    for path_text, content, purpose in files:
        path = REPO / path_text
        write_text(path, content)
        generated.append(
            {
                "path": rel(path),
                "status": "review_seed_only",
                "confidence": "unresolved",
                "purpose": purpose,
                "source_evidence": ["S07/security-lifecycle-model.json", "S07/stage-manifest.json"],
            }
        )
    return generated


def build_unresolved(security: dict[str, Any], hkip: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "id": "U-S08-REPO-0001",
            "kind": "production_source_blocked",
            "status": "unresolved",
            "reason": security["production_security_lifecycle"]["reason"],
            "source": "S07/security-lifecycle-model.json",
        },
        {
            "id": "U-S08-LC-0001",
            "kind": "vm_lifecycle_source_unresolved",
            "status": "unresolved",
            "reason": "S07 has lifecycle hypotheses only, not confirmed VM lifecycle transitions.",
            "source": "S07/lifecycle-model.json",
        },
        {
            "id": "U-S08-HKIP-0001",
            "kind": "hkip_source_unresolved",
            "status": "unresolved",
            "reason": f"S07 HKIP status is {hkip.get('status')}; no HKIP source can be synthesized.",
            "source": "S07/hkip-model.json",
        },
    ]


def main() -> None:
    manifest07 = read_json(S07 / "stage-manifest.json")
    security = read_json(S07 / "security-lifecycle-model.json")
    lifecycle = read_json(S07 / "lifecycle-model.json")
    hkip = read_json(S07 / "hkip-model.json")
    resource_transitions = read_jsonl(S07 / "resource-transitions.jsonl")

    generated_files = build_repo_files()
    unresolved = build_unresolved(security, hkip)

    recovery_index = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "status": "review_seed_repository_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "upstream": {
            "S07_status": manifest07.get("status"),
            "S07_s08_production": manifest07.get("s08_readiness", {}).get("production"),
            "S07_s08_review_seed": manifest07.get("s08_readiness", {}).get("review_seed"),
        },
        "generated_files": generated_files,
        "confirmed_source_units": [],
        "inferred_c_units": [],
        "asm_fallback_units": [row for row in generated_files if row["path"].endswith(".S")],
        "stub_units": [row for row in generated_files if row["path"].endswith(".c")],
        "unresolved_count": len(unresolved),
    }
    build_manifest = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "status": "metadata_only_not_build_validated",
        "reason": "Review-seed scaffold contains explicit unresolved stubs and no confirmed freestanding runtime.",
        "compiler_target": "aarch64-none-elf or equivalent freestanding toolchain",
        "buildable_claim": "not_claimed",
        "source_units": generated_files,
    }

    source_map = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "status": "review_seed_trace_map",
        "objects": [
            {
                "source_path": row["path"],
                "confidence_class": "unresolved" if not row["path"].endswith(".S") else "asm-fallback",
                "address_ranges": [],
                "evidence": row["source_evidence"],
                "note": "No address-to-source function mapping is claimed in S08-RW1.",
            }
            for row in generated_files
        ],
    }
    evidence_index = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "status": "review_seed_index",
        "evidence_sources": [
            "S07/stage-manifest.json",
            "S07/security-lifecycle-model.json",
            "S07/lifecycle-model.json",
            "S07/hkip-model.json",
            "S07/resource-transitions.jsonl",
        ],
        "resource_transition_hypotheses": len(resource_transitions),
        "lifecycle_hypotheses": len(lifecycle.get("review_seed_lifecycle_hypotheses", [])),
        "hkip_status": hkip.get("status"),
    }
    decision_index = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "decisions": [
            {
                "id": "D-S08-RW1-0001",
                "decision": "generate_unresolved_review_seed_scaffold",
                "rationale": "S07 review-seed is ready, but production lifecycle/HKIP recovery is blocked.",
            }
        ],
    }
    unknown_index = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "unknowns": unresolved,
    }
    coverage = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "status": "review_seed_only",
        "metrics": {
            "confirmed_source_units": 0,
            "inferred_c_units": 0,
            "asm_fallback_units": len(recovery_index["asm_fallback_units"]),
            "stub_units": len(recovery_index["stub_units"]),
            "unresolved_items": len(unresolved),
            "address_mapped_functions": 0,
        },
    }
    validation = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "result": "pass",
        "checks": [
            {
                "id": "S08-VAL-0001",
                "check": "no confirmed source units generated from review-seed S07",
                "result": "pass" if not recovery_index["confirmed_source_units"] and not recovery_index["inferred_c_units"] else "fail",
            },
            {
                "id": "S08-VAL-0002",
                "check": "unresolved index records production blockers",
                "result": "pass" if unresolved else "fail",
            },
            {
                "id": "S08-VAL-0003",
                "check": "source map avoids address-function claims",
                "result": "pass" if all(not row["address_ranges"] for row in source_map["objects"]) else "fail",
            },
        ],
    }
    validation["result"] = "pass" if all(row["result"] == "pass" for row in validation["checks"]) else "fail"

    stage_manifest = {
        "case_id": CASE_ID,
        "stage_id": "S08",
        "iteration_id": "S08-RW1",
        "producer_skill": "synthesize-hypervisor-repository",
        "status": "review_seed_repository_ready_production_blocked",
        "generated_at": now_iso(),
        "policy": POLICY,
        "inputs": [
            "S07/stage-manifest.json",
            "S07/security-lifecycle-model.json",
            "S07/lifecycle-model.json",
            "S07/hkip-model.json",
            "S07/resource-transitions.jsonl",
        ],
        "outputs": [
            "S08/recovered-repo/",
            "S08/recovery-index.json",
            "S08/build-manifest.json",
            "S08/source-map.json",
            "S08/address-to-source.json",
            "S08/evidence-to-source.json",
            "S08/coverage-summary.json",
            "S08/recovery-evidence-index.json",
            "S08/recovery-decision-index.json",
            "S08/recovery-unknown-index.json",
            "S08/unresolved-index.jsonl",
        ],
        "gates": {
            "production": {
                "status": "blocked",
                "reason": security["production_security_lifecycle"]["reason"],
            },
            "review_seed": {
                "status": "ready",
                "reason": "Generated unresolved repository scaffold and audit indexes only.",
            },
        },
        "s09_readiness": {
            "production": "blocked_no_confirmed_source_or_invariant_inputs",
            "review_seed": "ready_for_index_consistency_audit_only",
        },
    }

    write_json(S08 / "recovery-index.json", recovery_index)
    write_json(S08 / "build-manifest.json", build_manifest)
    write_json(S08 / "source-map.json", source_map)
    write_json(S08 / "address-to-source.json", {"case_id": CASE_ID, "stage_id": "S08", "mappings": []})
    write_json(
        S08 / "evidence-to-source.json",
        {
            "case_id": CASE_ID,
            "stage_id": "S08",
            "mappings": [
                {"evidence": ev, "source_paths": [row["path"] for row in generated_files]}
                for ev in evidence_index["evidence_sources"]
            ],
        },
    )
    write_json(S08 / "coverage-summary.json", coverage)
    write_json(S08 / "recovery-evidence-index.json", evidence_index)
    write_json(S08 / "recovery-decision-index.json", decision_index)
    write_json(S08 / "recovery-unknown-index.json", unknown_index)
    write_json(S08 / "artifact-validation-rw1.json", validation)
    write_json(S08 / "stage-manifest.json", stage_manifest)
    write_jsonl(S08 / "unresolved-index.jsonl", unresolved)

    print(
        json.dumps(
            {
                "stage": "S08",
                "iteration": "S08-RW1",
                "status": stage_manifest["status"],
                "validation": validation["result"],
                "generated_files": len(generated_files),
                "unresolved_items": len(unresolved),
                "s09_readiness": stage_manifest["s09_readiness"],
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
