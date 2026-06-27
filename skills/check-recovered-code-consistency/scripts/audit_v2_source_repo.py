#!/usr/bin/env python3
"""Audit workflow-v2 canonical source repository consistency.

This S09 helper treats the case directory as evidence workspace and the
recovered-repos/<case-id>/recovered-hypervisor directory as the user-facing
source repository. It does not mutate source or IDA state.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
FORBIDDEN_SOURCE_REPO_SUFFIXES = {".json", ".jsonl", ".sqlite", ".i64", ".idb"}


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows), encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def rel(path: Path) -> str:
    return path.as_posix()


def load_case(case_id: str) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    return {
        "case": case,
        "s09": case / "stages" / "S09",
        "delivery": read_json(s08 / "source-repo-delivery.json"),
        "function_map": read_json(s08 / "function-map.json"),
        "source_map": read_json(s08 / "source-map.json"),
        "quality": read_json(s08 / "source-quality-report.json"),
        "unresolved": read_jsonl(s08 / "unresolved-index.jsonl"),
    }


def scan_source_repo(repo: Path) -> dict[str, Any]:
    files = [p for p in sorted(repo.rglob("*")) if p.is_file()]
    by_suffix: dict[str, int] = {}
    for p in files:
        by_suffix[p.suffix.lower()] = by_suffix.get(p.suffix.lower(), 0) + 1
    forbidden = [rel(p.relative_to(repo)) for p in files if p.suffix.lower() in FORBIDDEN_SOURCE_REPO_SUFFIXES]
    return {
        "path": rel(repo.relative_to(ROOT)),
        "exists": repo.exists(),
        "files": [{"path": rel(p.relative_to(repo)), "size": p.stat().st_size} for p in files],
        "file_count": len(files),
        "suffix_counts": by_suffix,
        "c_files": [rel(p.relative_to(repo)) for p in files if p.suffix == ".c"],
        "h_files": [rel(p.relative_to(repo)) for p in files if p.suffix == ".h"],
        "forbidden_artifacts": forbidden,
    }


def symbol_present(repo: Path, source_file: str, symbol: str) -> bool:
    path = repo / source_file
    if not path.exists():
        return False
    text = path.read_text(encoding="utf-8", errors="replace")
    return bool(re.search(r"(^|\n)uintptr_t\s+" + re.escape(symbol) + r"\s*\(", text))


def scan_source_function_defs(repo: Path) -> dict[str, list[str]]:
    defs: dict[str, list[str]] = {}
    pattern = re.compile(r"^uintptr_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", flags=re.MULTILINE)
    for path in sorted(repo.rglob("*.c")):
        rel_path = rel(path.relative_to(repo))
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in pattern.finditer(text):
            defs.setdefault(match.group(1), []).append(rel_path)
    return defs


def read_source_text(repo: Path, source_file: str) -> str:
    path = repo / source_file
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def source_evidence_metadata(text: str, symbol: str) -> dict[str, str] | None:
    """Read the evidence comment metadata nearest to a source function."""

    match = re.search(r"(^|\n)uintptr_t\s+" + re.escape(symbol) + r"\s*\(", text)
    if not match:
        return None
    prefix = text[: match.start()]
    comments = list(
        re.finditer(
            r"/\* evidence: image offset (?P<addr>0x[0-9a-fA-F]+), IDA [^,]+, range [^,]+, confidence (?P<confidence>[^,]+), class (?P<class>[a-zA-Z0-9_-]+) \*/",
            prefix,
        )
    )
    if not comments:
        return None
    comment = comments[-1]
    return {"addr": comment.group("addr"), "class": comment.group("class"), "confidence": comment.group("confidence")}


def source_function_body(text: str, symbol: str) -> str | None:
    match = re.search(
        r"uintptr_t\s+" + re.escape(symbol) + r"\s*\(struct recovered_context \*ctx\)\s*\{(?P<body>.*?)\n\}",
        text,
        flags=re.DOTALL,
    )
    return match.group("body") if match else None


def audit(case_id: str) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], str]:
    inputs = load_case(case_id)
    delivery = inputs["delivery"]
    repo = ROOT / delivery["canonical_source_repo"]
    repo_scan = scan_source_repo(repo)
    functions = inputs["function_map"].get("functions", [])
    source_functions = inputs["source_map"].get("function_sources", [])
    diagnostic_rows = read_jsonl(inputs["case"] / "stages" / "S08" / "diagnostic-summary-rewrite-index.jsonl")

    findings: list[dict[str, Any]] = []
    if not repo_scan["exists"]:
        findings.append({"id": "S09-SRC-0001", "severity": "error", "kind": "missing_canonical_source_repo"})
    if not repo_scan["c_files"]:
        findings.append({"id": "S09-SRC-0002", "severity": "error", "kind": "missing_c_files"})
    if not repo_scan["h_files"]:
        findings.append({"id": "S09-SRC-0003", "severity": "error", "kind": "missing_h_files"})
    if repo_scan["forbidden_artifacts"]:
        findings.append(
            {
                "id": "S09-SRC-0004",
                "severity": "error",
                "kind": "intermediate_artifacts_in_source_repo",
                "paths": repo_scan["forbidden_artifacts"],
            }
        )

    source_defs = scan_source_function_defs(repo) if repo.exists() else {}
    duplicate_defs = {
        symbol: sorted(set(paths))
        for symbol, paths in source_defs.items()
        if len(set(paths)) > 1
    }
    for symbol, paths in sorted(duplicate_defs.items()):
        findings.append(
            {
                "id": f"S09-DUP-SYM-{symbol}",
                "severity": "error",
                "kind": "duplicate_source_symbol_definition",
                "symbol": symbol,
                "sources": paths,
            }
        )

    mapped_by_addr = {row["function"].lower(): row for row in source_functions}
    source_text_cache: dict[str, str] = {}
    for f in functions:
        addr = f["address"].lower()
        mapping = mapped_by_addr.get(addr)
        if not mapping:
            findings.append({"id": f"S09-MAP-{addr}", "severity": "error", "kind": "missing_source_map_entry", "address": addr})
            continue
        if not symbol_present(repo, mapping["source"], mapping["symbol"]):
            findings.append(
                {
                    "id": f"S09-SYM-{addr}",
                    "severity": "error",
                    "kind": "mapped_symbol_not_found_in_source",
                    "address": addr,
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )
            continue
        if mapping.get("output_class") != f.get("output_class"):
            findings.append(
                {
                    "id": f"S09-CLASS-MAP-{addr}",
                    "severity": "error",
                    "kind": "function_map_source_map_output_class_mismatch",
                    "address": addr,
                    "function_map_class": f.get("output_class"),
                    "source_map_class": mapping.get("output_class"),
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )
        text = source_text_cache.setdefault(mapping["source"], read_source_text(repo, mapping["source"]))
        comment_metadata = source_evidence_metadata(text, mapping["symbol"])
        if comment_metadata is None:
            findings.append(
                {
                    "id": f"S09-CLASS-COMMENT-MISSING-{addr}",
                    "severity": "warning",
                    "kind": "source_evidence_class_missing",
                    "address": addr,
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )
        elif comment_metadata["addr"].lower() != addr:
            findings.append(
                {
                    "id": f"S09-ADDR-COMMENT-{addr}",
                    "severity": "error",
                    "kind": "function_map_source_comment_address_mismatch",
                    "address": addr,
                    "source_comment_address": comment_metadata["addr"].lower(),
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )
        elif comment_metadata["class"] != f.get("output_class"):
            findings.append(
                {
                    "id": f"S09-CLASS-COMMENT-{addr}",
                    "severity": "error",
                    "kind": "function_map_source_comment_output_class_mismatch",
                    "address": addr,
                    "function_map_class": f.get("output_class"),
                    "source_comment_class": comment_metadata["class"],
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )
        if comment_metadata is not None and comment_metadata["confidence"] != f.get("confidence"):
            findings.append(
                {
                    "id": f"S09-CONFIDENCE-COMMENT-{addr}",
                    "severity": "error",
                    "kind": "function_map_source_comment_confidence_mismatch",
                    "address": addr,
                    "function_map_confidence": f.get("confidence"),
                    "source_comment_confidence": comment_metadata["confidence"],
                    "source": mapping["source"],
                    "symbol": mapping["symbol"],
                }
            )

    functions_by_addr = {f["address"].lower(): f for f in functions}
    for row in diagnostic_rows:
        if not row.get("applied"):
            continue
        addr = str(row.get("address", "")).lower()
        fn = functions_by_addr.get(addr)
        if not fn:
            findings.append({"id": f"S09-DIAG-{addr}", "severity": "error", "kind": "diagnostic_rewrite_missing_function", "address": addr})
            continue
        text = source_text_cache.setdefault(fn["source_file"], read_source_text(repo, fn["source_file"]))
        body = source_function_body(text, fn["source_symbol"])
        if not body or "diagnostic-summary rewrite" not in body:
            findings.append(
                {
                    "id": f"S09-DIAG-BODY-{addr}",
                    "severity": "error",
                    "kind": "diagnostic_rewrite_body_missing_marker",
                    "address": addr,
                    "source": fn["source_file"],
                    "symbol": fn["source_symbol"],
                }
            )
        if fn.get("output_class") != "semantic-c":
            findings.append(
                {
                    "id": f"S09-DIAG-CLASS-{addr}",
                    "severity": "error",
                    "kind": "diagnostic_rewrite_not_semantic_c",
                    "address": addr,
                    "output_class": fn.get("output_class"),
                }
            )

    if inputs["quality"].get("fake_stub_files", 0) != 0:
        findings.append({"id": "S09-SRC-0005", "severity": "error", "kind": "fake_stub_files_nonzero"})
    if inputs["quality"].get("codegen_ready_without_source", 0) != 0:
        findings.append({"id": "S09-SRC-0006", "severity": "error", "kind": "codegen_ready_without_source_nonzero"})
    if inputs["unresolved"]:
        findings.append({"id": "S09-SRC-0007", "severity": "warning", "kind": "unresolved_entries_remain", "count": len(inputs["unresolved"])})

    status = "pass" if not [f for f in findings if f["severity"] == "error"] else "fail"
    source_repo_audit = {
        "case_id": case_id,
        "stage_id": "S09",
        "iteration_id": "S09-V2-RW1",
        "generated_at": now_iso(),
        "status": status,
        "canonical_source_repo": delivery["canonical_source_repo"],
        "policy": "Canonical source repo must contain source/build files and no JSON/JSONL/IDA/SQLite intermediate artifacts.",
        "repo_scan": repo_scan,
        "function_count": len(functions),
        "source_map_function_count": len(source_functions),
        "source_function_def_count": sum(len(paths) for paths in source_defs.values()),
        "unique_source_function_symbol_count": len(source_defs),
        "duplicate_source_symbol_count": len(duplicate_defs),
        "finding_count": len(findings),
    }
    consistency_report = {
        "case_id": case_id,
        "stage_id": "S09",
        "iteration_id": "S09-V2-RW1",
        "generated_at": now_iso(),
        "status": status,
        "checks": [
            {
                "id": "S09-V2-CHECK-SOURCE-REPO-PURITY",
                "result": "pass" if not repo_scan["forbidden_artifacts"] else "fail",
                "summary": "Canonical source repository contains no JSON/JSONL/IDA/SQLite intermediate artifacts.",
            },
            {
                "id": "S09-V2-CHECK-SOURCE-PRESENCE",
                "result": "pass" if repo_scan["c_files"] and repo_scan["h_files"] else "fail",
                "summary": "Canonical source repository contains at least one .c and one .h file.",
            },
            {
                "id": "S09-V2-CHECK-FUNCTION-MAP-COVERAGE",
                "result": "pass" if len(source_functions) == len(functions) else "fail",
                "summary": "Every function-map entry has a source-map entry.",
            },
            {
                "id": "S09-V2-CHECK-SYMBOL-READBACK",
                "result": "pass" if not [f for f in findings if f["kind"] == "mapped_symbol_not_found_in_source"] else "fail",
                "summary": "Every source-map symbol is present in the canonical source repo.",
            },
            {
                "id": "S09-V2-CHECK-UNIQUE-SOURCE-SYMBOLS",
                "result": "pass" if not duplicate_defs else "fail",
                "summary": "Every primary recovered source symbol has exactly one canonical definition.",
            },
            {
                "id": "S09-V2-CHECK-OUTPUT-CLASS-CONSISTENCY",
                "result": "pass"
                if not [
                    f
                    for f in findings
                    if f["kind"]
                    in {
                        "function_map_source_map_output_class_mismatch",
                        "function_map_source_comment_output_class_mismatch",
                        "function_map_source_comment_address_mismatch",
                        "function_map_source_comment_confidence_mismatch",
                        "diagnostic_rewrite_not_semantic_c",
                    }
                ]
                else "fail",
                "summary": "Function-map, source-map, source comments, and diagnostic rewrite indexes agree on output classes and confidence metadata.",
            },
            {
                "id": "S09-V2-CHECK-DIAGNOSTIC-REWRITE-BODY",
                "result": "pass" if not [f for f in findings if f["kind"] == "diagnostic_rewrite_body_missing_marker"] else "fail",
                "summary": "Every applied diagnostic summary rewrite has a matching source body marker.",
            },
        ],
        "source_repo_audit": "S09/source-repo-audit.json",
        "finding_count": len(findings),
    }
    md = f"""# S09 Static Audit Report: Workflow v2 Source Repository

Case: `{case_id}`

Status: `{status}`

## Canonical source repository

`{delivery['canonical_source_repo']}`

This directory is the user-facing source repository. The case directory remains the evidence workspace.

## Source repo purity

- Files: `{repo_scan['file_count']}`
- `.c` files: `{len(repo_scan['c_files'])}`
- `.h` files: `{len(repo_scan['h_files'])}`
- Forbidden intermediate artifacts: `{len(repo_scan['forbidden_artifacts'])}`

## Function/source mapping

- Function-map entries: `{len(functions)}`
- Source-map function entries: `{len(source_functions)}`
- Source function definitions: `{sum(len(paths) for paths in source_defs.values())}`
- Unique source function symbols: `{len(source_defs)}`
- Duplicate source symbols: `{len(duplicate_defs)}`
- Fake stub files: `{inputs['quality'].get('fake_stub_files', 0)}`
- Codegen-ready without source: `{inputs['quality'].get('codegen_ready_without_source', 0)}`
- Unresolved entries: `{len(inputs['unresolved'])}`

## Recommendation

Proceed to S10 packaging only with the canonical source repository path above. Do not package `cases/<case>/stages` as the source repo; it is evidence and audit material.
"""
    return source_repo_audit, consistency_report, findings, md


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    args = ap.parse_args()
    source_repo_audit, consistency_report, findings, md = audit(args.case_id)
    s09 = ROOT / "cases" / args.case_id / "stages" / "S09"
    write_json(s09 / "source-repo-audit.json", source_repo_audit)
    write_json(s09 / "consistency-report.json", consistency_report)
    write_jsonl(s09 / "model-source-mismatches.jsonl", findings)
    write_jsonl(s09 / "audit-findings.jsonl", findings)
    write_text(s09 / "static-audit-report.md", md)
    write_json(
        s09 / "static-audit-report.json",
        {
            "case_id": args.case_id,
            "stage_id": "S09",
            "iteration_id": "S09-V2-RW1",
            "status": source_repo_audit["status"],
            "canonical_source_repo": source_repo_audit["canonical_source_repo"],
            "finding_count": len(findings),
            "recommendation": "package_canonical_source_repo_only",
        },
    )
    write_json(
        s09 / "stage-manifest.json",
        {
            "case_id": args.case_id,
            "stage_id": "S09",
            "iteration_id": "S09-V2-RW1",
            "status": "source_repo_audit_ready" if source_repo_audit["status"] == "pass" else "source_repo_audit_failed",
            "canonical_source_repo": source_repo_audit["canonical_source_repo"],
            "outputs": [
                "S09/source-repo-audit.json",
                "S09/consistency-report.json",
                "S09/model-source-mismatches.jsonl",
                "S09/static-audit-report.json",
                "S09/static-audit-report.md",
                "S09/audit-findings.jsonl",
            ],
        },
    )
    print(json.dumps({"case": args.case_id, "status": source_repo_audit["status"], "findings": len(findings)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
