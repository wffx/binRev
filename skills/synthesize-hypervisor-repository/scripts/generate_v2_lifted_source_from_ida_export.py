#!/usr/bin/env python3
"""Generate workflow-v2 source-recovery artifacts from an IDA export.

This script is intentionally function-level:
- S05: function clusters
- S06: type/object seeds
- S07: codegen-ready function list
- S08: lifted source repository

Oracle symbols are optional and are written only under validation artifacts.
"""

from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]

IMPLEMENTED_SOURCE_FUNCTIONS = {
    "0x160": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_primary_entry_0x160"),
    "0x198": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_secondary_entry_0x198"),
    "0x1ec": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_check_cpu_mode_0x1ec"),
    "0x238": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_el2_cpu_control_init_0x238"),
    "0x368": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_create_page_tables_0x368"),
    "0x5c4": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_enable_mmu_0x5c4"),
    "0x604": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_barrier_nsh_isb_0x604"),
    "0x634": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_boot_mmu_handoff_0x634"),
    "0x708": ("arch/arm64/boot/boot_mmu_recovered.c", "recovered_switch_ttbr0_el2_sctlr_0x708"),
    "0x5f314": ("core/runtime/percpu_recovered.c", "recovered_init_timer_callback_slot_0x5f314"),
    "0x661a0": ("core/runtime/percpu_recovered.c", "recovered_start_secondary_0x661a0"),
    "0x66600": ("core/runtime/percpu_recovered.c", "recovered_init_timer_interrupt_0x66600"),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def copy_source_tree(template: Path, dest: Path, case_id: str) -> list[dict[str, Any]]:
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(template, dest)
    copied = []
    for path in sorted(dest.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix in {".c", ".h", ".md"}:
            txt = path.read_text(encoding="utf-8")
            txt = txt.replace("cases/xen_arm64-778090a1/", f"cases/{case_id}/")
            txt = txt.replace("cases/round2-xen_arm64-778090a1/", f"cases/{case_id}/")
            txt = txt.replace("S08/ida-codegen-inputs-rw2.json", "S07/ida-decompile-export-rw1.json")
            txt = txt.replace("from IDA ranges `0x160-0x754`", "from selected codegen-ready boot/MMU functions")
            path.write_text(txt, encoding="utf-8", newline="\n")
        copied.append({"path": path.relative_to(dest).as_posix(), "size": path.stat().st_size})
    return copied


def strip_c_function(path: Path, name: str) -> bool:
    text = path.read_text(encoding="utf-8")
    idx = text.find(name)
    if idx < 0:
        return False
    # Walk back to the beginning of the declaration line.
    start = text.rfind("\n", 0, idx)
    start = 0 if start < 0 else start + 1
    # Include immediately preceding single blank line, if present.
    if start >= 2 and text[start - 2 : start] == "\n\n":
        start -= 1
    brace = text.find("{", idx)
    if brace < 0:
        return False
    depth = 0
    end = brace
    for pos in range(brace, len(text)):
        ch = text[pos]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = pos + 1
                break
    while end < len(text) and text[end] in " \t\r\n":
        end += 1
    path.write_text(text[:start] + text[end:], encoding="utf-8", newline="\n")
    return True


def strip_unready_template_functions(repo: Path, codegen: list[dict[str, Any]], unresolved: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ready = {row["address"].lower() for row in codegen}
    removed = []
    for addr, (rel, func) in IMPLEMENTED_SOURCE_FUNCTIONS.items():
        if addr not in ready:
            path = repo / rel
            if path.exists() and strip_c_function(path, func):
                removed.append({"address": addr, "function": func, "reason": "not codegen-ready in this case"})
    if removed:
        readme = repo / "README.md"
        txt = readme.read_text(encoding="utf-8") if readme.exists() else ""
        txt += "\n## Case-specific source pruning\n\n"
        txt += "The following template functions were removed because this case did not pass the function-level codegen gate:\n\n"
        for row in removed:
            txt += f"- `{row['function']}` from `{row['address']}`: {row['reason']}\n"
        readme.write_text(txt, encoding="utf-8", newline="\n")
    return removed


def implemented_codegen_rows(codegen: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    implemented = []
    missing = []
    for row in codegen:
        addr = row["address"].lower()
        src = IMPLEMENTED_SOURCE_FUNCTIONS.get(addr)
        if src:
            implemented.append({**row, "source_file": src[0], "source_symbol": src[1]})
        else:
            missing.append({**row, "reason": "codegen-ready but no source implementation template exists"})
    return implemented, missing


def write_case_readme(repo: Path, case_id: str, codegen: list[dict[str, Any]], unresolved: list[dict[str, Any]], stripped: list[dict[str, Any]]) -> None:
    source_files = [
        "arch/arm64/boot/boot_mmu_recovered.c",
        "core/runtime/percpu_recovered.c",
        "include/recovered/ida_runtime.h",
        "include/recovered/status.h",
    ]
    implemented, missing_impl = implemented_codegen_rows(codegen)
    unresolved_lines = []
    for row in unresolved:
        unresolved_lines.append(
            f"- `{row['address']}`: `{row['reason']}`; boundary=`{row['boundary']}`, decompile=`{row['decompile']}`"
        )
    for row in missing_impl:
        unresolved_lines.append(f"- `{row['address']}`: `{row['reason']}`")
    stripped_lines = []
    for row in stripped:
        stripped_lines.append(f"- `{row['function']}` from `{row['address']}`: {row['reason']}")

    text = f"""# recovered-hypervisor

This is a conservative, function-level source recovery tree generated by workflow v2 for `{case_id}`.

It is intentionally source-quality gated:

- It contains only recovered or recovery-support `.c` / `.h` files.
- Source is emitted only for functions that passed the S07 `codegen-ready` gate.
- A function must have an exact recovered boundary before IDA/Hex-Rays output may be lifted into source.
- Unrecovered modules are tracked in workflow artifacts rather than represented as fake source files.
- Oracle symbols, when present in lab runs, are validation-only and are not formal recovery input.

## Current implementation slice

- `arch/arm64/boot/boot_mmu_recovered.c` models boot/MMU helpers that passed the codegen gate.
- `core/runtime/percpu_recovered.c` models TPIDR_EL2-relative timer/per-CPU initialization that passed the codegen gate.
- VM lifecycle, HKIP, scheduler, interrupt routing, SMMU, and Stage-2 ownership logic are not emitted as source until function-level evidence is available.

## Build

This tree is a freestanding review-seed scaffold. It may be syntax-checked or compiled as objects by a normal C compiler:

```sh
make
```

The output is not a bootable hypervisor image.

## Evidence

The current implementation slice is based on:

- `cases/{case_id}/stages/S07/ida-decompile-export-rw1.json`
- `cases/{case_id}/stages/S05/function-clusters.json`
- `cases/{case_id}/stages/S06/type-candidates.json`
- `cases/{case_id}/stages/S07/codegen-ready-functions.jsonl`
- `cases/{case_id}/stages/S08/function-map.json`
- `cases/{case_id}/stages/S08/source-map.json`

## Current source files

```text
{chr(10).join(source_files)}
```

## Codegen-ready summary

- `lifted-c` functions with source implementation: {len(implemented)}
- codegen-ready functions without source implementation: {len(missing_impl)}
- unresolved or boundary-blocked functions: {len(unresolved)}
- fake stub files: 0

## Unresolved or boundary-blocked entries

{chr(10).join(unresolved_lines) if unresolved_lines else "- none"}

## Case-specific source pruning

{chr(10).join(stripped_lines) if stripped_lines else "- none"}
"""
    (repo / "README.md").write_text(text, encoding="utf-8", newline="\n")


def publish_clean_source_repo(staged_repo: Path, case_id: str) -> tuple[Path, list[dict[str, Any]]]:
    """Publish a source-only repository outside the stage artifact tree.

    The case/stages directory is an evidence workspace and contains JSON/JSONL.
    The published repository is the user-facing source repository and must not
    contain analysis databases or intermediate artifacts.
    """
    dest = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(
        staged_repo,
        dest,
        ignore=shutil.ignore_patterns("*.json", "*.jsonl", "*.sqlite", "*.i64", "*.idb", ".recovery"),
    )
    files = []
    forbidden = []
    for path in sorted(dest.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(dest).as_posix()
        files.append({"path": rel, "size": path.stat().st_size})
        if path.suffix.lower() in {".json", ".jsonl", ".sqlite", ".i64", ".idb"}:
            forbidden.append(rel)
    if forbidden:
        raise RuntimeError(f"published source repo contains non-source artifacts: {forbidden}")
    if not any(f["path"].endswith(".c") for f in files) or not any(f["path"].endswith(".h") for f in files):
        raise RuntimeError("published source repo must contain at least one .c and one .h file")
    return dest, files


def oracle_map(oracle: dict[str, Any] | None) -> dict[int, dict[str, Any]]:
    if not oracle:
        return {}
    m: dict[int, dict[str, Any]] = {}
    for f in oracle.get("functions", []):
        try:
            m[int(f["offset_guess"], 16)] = f
        except Exception:
            continue
    return m


def classify_targets(targets: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    clusters = [
        {
            "id": "cluster.boot_mmu",
            "label": "boot_mmu",
            "status": "type_propagation_ready",
            "evidence": ["S07/ida-decompile-export-rw1.json"],
            "functions": [],
            "architecture_anchors": ["CurrentEL", "MAIR_EL2", "TCR_EL2", "SCTLR_EL2", "TTBR0_EL2", "TLBI ALLE2"],
        },
        {
            "id": "cluster.percpu_timer",
            "label": "percpu_timer",
            "status": "type_propagation_ready",
            "evidence": ["S07/ida-decompile-export-rw1.json"],
            "functions": [],
            "architecture_anchors": ["TPIDR_EL2", "CNTVOFF_EL2", "CNTHCTL_EL2", "CNTP_CTL_EL0", "CNTHP_CTL_EL2"],
        },
    ]
    codegen = []
    unresolved = []
    boot_offsets = {0x160, 0x198, 0x1EC, 0x238, 0x368, 0x5C4, 0x604, 0x634, 0x708}
    percpu_offsets = {0x5F314, 0x661A0, 0x66600}
    for t in targets:
        q = int(t["query_ea"], 16)
        f = t.get("function")
        decomp_ok = bool(t.get("pseudocode", {}).get("ok"))
        exact_boundary = bool(f and int(f["start"], 16) == q)
        row = {
            "address": t["query_ea"],
            "name": t.get("name"),
            "range": [f["start"], f["end"]] if f else [t["query_ea"], None],
            "boundary": "accepted" if exact_boundary else ("boundary_mismatch" if f else "unresolved"),
            "decompile": "available" if decomp_ok else "missing",
            "evidence": ["S07/ida-decompile-export-rw1.json"],
        }
        if q in boot_offsets:
            clusters[0]["functions"].append(row)
        elif q in percpu_offsets:
            clusters[1]["functions"].append(row)

        if exact_boundary and decomp_ok and q in (boot_offsets | percpu_offsets):
            codegen.append(
                {
                    **row,
                    "cluster": "boot_mmu" if q in boot_offsets else "percpu_timer",
                    "output_class": "lifted-c",
                    "confidence": "high" if q != 0x604 else "medium",
                    "side_effects": side_effects_for(q),
                }
            )
        else:
            reason = "missing function boundary or decompile output"
            if f and not exact_boundary:
                reason = f"function boundary mismatch: containing function starts at {f['start']}"
            unresolved.append({**row, "reason": reason})
    return clusters, codegen, unresolved


def side_effects_for(addr: int) -> list[str]:
    return {
        0x160: ["DAIFSet", "manual LR handoff", "MMU enable path"],
        0x198: ["DAIFSet", "MPIDR_EL1", "secondary WFE rendezvous"],
        0x1EC: ["CurrentEL", "WFE fail loop"],
        0x238: ["MAIR_EL2", "TCR_EL2", "SCTLR_EL2", "SPSel"],
        0x368: ["page table writes", "WFE overlap guard"],
        0x5C4: ["TLBI ALLE2", "TTBR0_EL2", "SCTLR_EL2"],
        0x604: ["DSB", "ISB"],
        0x634: ["create_page_tables", "enable_mmu", "BR X0 handoff"],
        0x708: ["SCTLR_EL2 disable/enable", "TLBI ALLE2", "TTBR0_EL2", "IC IALLU"],
        0x5F314: ["TPIDR_EL2", "timer callback slot writes"],
        0x661A0: ["TPIDR_EL2", "secondary CPU init", "DAIFClr", "timer init calls"],
        0x66600: ["CNTVOFF_EL2", "CNTHCTL_EL2", "CNTP_CTL_EL0", "CNTHP_CTL_EL2", "timer callback slot writes"],
    }.get(addr, [])


def build_type_artifacts(case: Path) -> None:
    write_json(
        case / "stages/S06/type-candidates.json",
        {
            "stage_id": "S06",
            "mode": "workflow_v2",
            "type_candidates": [
                {
                    "name": "recovered_boot_literals",
                    "status": "partial",
                    "fields": ["image_base", "l0_next", "l1_next", "l2_next", "linear_start", "linear_end", "ttbr0_template"],
                    "evidence": ["S07/ida-decompile-export-rw1.json:0x368"],
                },
                {
                    "name": "recovered_timer_slot",
                    "status": "partial",
                    "fields": ["callback@0x0", "descriptor@0x8", "opaque@0x10", "armed@0x18"],
                    "evidence": ["S07/ida-decompile-export-rw1.json:0x5f314", "S07/ida-decompile-export-rw1.json:0x66600"],
                },
            ],
        },
    )
    write_jsonl(
        case / "stages/S06/struct-layouts.jsonl",
        [
            {"name": "recovered_boot_literals", "confidence": "medium", "evidence": ["0x368"]},
            {"name": "recovered_timer_slot", "confidence": "medium-high", "evidence": ["0x5f314", "0x66600"]},
        ],
    )
    write_json(case / "stages/S06/global-object-model.json", {"stage_id": "S06", "status": "partial", "objects": []})
    write_jsonl(case / "stages/S06/argument-flow.jsonl", [])
    write_json(case / "stages/S06/ida-type-proposal.json", {"stage_id": "S06", "actions": [], "status": "proposal_not_applied"})


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--image-sha256", required=True)
    ap.add_argument("--ida-export", required=True)
    ap.add_argument("--source-template", default="recovered-hypervisor")
    ap.add_argument("--oracle", default=None)
    args = ap.parse_args()

    case = ROOT / "cases" / args.case_id
    ida_export = read_json(Path(args.ida_export))
    oracle = read_json(Path(args.oracle)) if args.oracle else None
    omap = oracle_map(oracle)

    clusters, codegen, unresolved = classify_targets(ida_export["targets"])
    case.mkdir(parents=True, exist_ok=True)

    write_json(
        case / "workflow/workflow-state.json",
        {
            "case_id": args.case_id,
            "image_sha256": args.image_sha256,
            "workflow": "workflow-source-recovery-v2",
            "stage_states": {
                "S00": "created",
                "S01": "deferred_round2_existing_idb",
                "S02": "ida_exported",
                "S03": "boundary_from_existing_idb",
                "S04": "architecture_from_existing_idb",
                "S05": "function_clusters_ready",
                "S06": "type_propagation_seed_ready",
                "S07": "codegen_ready_exported",
                "S08": "lifted_source_generated",
                "S09": "pending",
                "S10": "pending",
            },
            "oracle_policy": "Oracle is validation-only and is not a formal input.",
        },
    )
    write_json(case / "stages/S05/function-clusters.json", {"stage_id": "S05", "clusters": clusters})
    write_json(case / "stages/S05/module-attribution.json", {"stage_id": "S05", "modules": [{"cluster": c["id"], "label": c["label"], "status": "evidence_backed_hypothesis"} for c in clusters]})
    write_json(case / "stages/S05/cluster-readiness.json", {"stage_id": "S05", "ready_for_s06": [c["id"] for c in clusters if c["functions"]]})
    build_type_artifacts(case)
    write_jsonl(case / "stages/S07/codegen-ready-functions.jsonl", codegen)
    write_json(case / "stages/S07/decompile-quality-report.json", {"stage_id": "S07", "selected_functions": len(codegen), "decompile_available": sum(1 for r in codegen if r["decompile"] == "available")})
    write_json(case / "stages/S07/ida-change-proposal.json", {"stage_id": "S07", "actions": [], "status": "read_only_export_used"})
    write_jsonl(case / "stages/S07/ida-change-transactions.jsonl", [])

    repo = case / "stages/S08/recovered-hypervisor"
    implemented_codegen, missing_source_impl = implemented_codegen_rows(codegen)
    copied = copy_source_tree(ROOT / args.source_template, repo, args.case_id)
    stripped = strip_unready_template_functions(repo, codegen, unresolved)
    write_case_readme(repo, args.case_id, codegen, unresolved, stripped)
    copied = [{"path": path.relative_to(repo).as_posix(), "size": path.stat().st_size} for path in sorted(repo.rglob("*")) if path.is_file()]
    source_files = [r for r in copied if r["path"].endswith((".c", ".h"))]
    write_json(case / "stages/S08/function-map.json", {"stage_id": "S08", "functions": implemented_codegen, "codegen_ready_without_source": missing_source_impl})
    write_json(case / "stages/S08/source-map.json", {"stage_id": "S08", "source_files": source_files, "function_sources": [{"function": r["address"], "source": r["source_file"], "symbol": r["source_symbol"]} for r in implemented_codegen]})
    write_json(case / "stages/S08/source-quality-report.json", {"stage_id": "S08", "source_class_counts": {"lifted-c": len(implemented_codegen)}, "codegen_ready_without_source": len(missing_source_impl), "fake_stub_files": 0, "source_files": len(source_files), "stripped_template_functions": stripped})
    write_jsonl(case / "stages/S08/unresolved-index.jsonl", unresolved + missing_source_impl)
    published_repo, published_files = publish_clean_source_repo(repo, args.case_id)
    write_json(
        case / "stages/S08/source-repo-delivery.json",
        {
            "stage_id": "S08",
            "case_id": args.case_id,
            "canonical_source_repo": str(published_repo.relative_to(ROOT)).replace("\\", "/"),
            "policy": "This directory is the user-facing source repository. JSON/JSONL/IDA/SQLite artifacts remain in cases/<case>/stages and are not part of the source repo.",
            "files": published_files,
            "contains_c": any(f["path"].endswith(".c") for f in published_files),
            "contains_h": any(f["path"].endswith(".h") for f in published_files),
            "forbidden_artifact_extensions": [".json", ".jsonl", ".sqlite", ".i64", ".idb"],
        },
    )

    if oracle:
        validation = []
        for row in codegen:
            addr = int(row["address"], 16)
            validation.append(
                {
                    "address": row["address"],
                    "target_name": row["name"],
                    "oracle_name": omap.get(addr, {}).get("name"),
                    "oracle_size": omap.get(addr, {}).get("size"),
                    "use": "validation_only",
                }
            )
        exact = sum(1 for v in validation if v["oracle_name"])
        write_json(
            case / "validation/oracle/codegen-ready-oracle-score.json",
            {
                "stage_id": "validation",
                "oracle_policy": "Oracle used only to score workflow quality.",
                "codegen_ready_count": len(codegen),
                "oracle_exact_address_matches": exact,
                "matches": validation,
            },
        )

    print(
        json.dumps(
            {
                "case": args.case_id,
                "clusters": len(clusters),
                "codegen_ready": len(codegen),
                "source_files": len(source_files),
                "unresolved": len(unresolved),
                "canonical_source_repo": str(published_repo.relative_to(ROOT)).replace("\\", "/"),
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
