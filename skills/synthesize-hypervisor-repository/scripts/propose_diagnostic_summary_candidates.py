#!/usr/bin/env python3
"""Propose lifted functions suitable for diagnostic-summary rewrite.

This helper is read-only.  It mines externalized Hex-Rays pseudocode for
string/log/trap-heavy functions whose exact dataflow is still too complex for
faithful C lifting, but whose user-visible responsibility is likely recoverable
as a conservative diagnostic summary.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def classify_terms(pseudocode: str) -> list[str]:
    text = pseudocode.lower()
    classes: list[str] = []
    for key, words in {
        "debug_key": ["pressed", "debug", "key"],
        "console_log": ["console", "log", "guest", "standard"],
        "reboot": ["reboot", "noreboot"],
        "interrupt": ["irq", "interrupt"],
        "fault_or_trap": ["division", "zero", "fault", "abort", "__break"],
        "scheduler": ["scheduler", "credit", "runqueue", "load_window", "load tracking"],
        "memory_report": ["physical memory", "heap", "dma"],
        "version_banner": ["xen version", "changeset", "build-id"],
        "device_tree": ["compatible", "ranges", "interrupt-cells", "address-cells", "size-cells"],
        "device_tree_pci": ["pciex", "pcie", "pci", "device"],
    }.items():
        if any(word in text for word in words):
            classes.append(key)
    return classes


def evidence_terms(pseudocode: str, limit: int = 12) -> list[str]:
    literals = re.findall(r'"(?:[^"\\]|\\.){4,}"', pseudocode)
    labels = re.findall(r"\ba[A-Z][A-Za-z0-9_]{3,}\b", pseudocode)
    calls = re.findall(r"\bsub_[0-9A-Fa-f]+\b", pseudocode)
    ordered: list[str] = []
    for item in literals + labels + calls:
        if item not in ordered:
            ordered.append(item)
        if len(ordered) >= limit:
            break
    return ordered


def line_count(text: str) -> int:
    return len([line for line in text.splitlines() if line.strip()])


def propose(case_id: str, source_file: str | None, limit: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s08 = case / "stages" / "S08"
    fmap = read_json(s08 / "function-map.json")
    functions = {fn["address"].lower(): fn for fn in fmap.get("functions", [])}
    applied_diag = {
        row.get("address", "").lower()
        for row in read_jsonl(s08 / "diagnostic-summary-rewrite-index.jsonl")
        if row.get("applied")
    }

    rows: list[dict[str, Any]] = []
    for row in read_jsonl(s08 / "lifted-pseudocode-review.jsonl"):
        addr = row.get("address", "").lower()
        fn = functions.get(addr)
        if not fn or fn.get("output_class") != "lifted-c":
            continue
        if addr in applied_diag:
            continue
        if source_file and row.get("source_file") != source_file:
            continue
        pseudocode = row.get("pseudocode", "")
        log_calls = len(re.findall(r"\bsub_1C18\s*\(", pseudocode))
        calls = len(re.findall(r"\bsub_[0-9A-Fa-f]+\s*\(", pseudocode))
        branches = len(re.findall(r"\bif\s*\(|\bfor\s*\(|\bwhile\s*\(|\bswitch\s*\(", pseudocode))
        traps = len(re.findall(r"__break|BUG|panic|fault|abort", pseudocode, flags=re.IGNORECASE))
        terms = evidence_terms(pseudocode)
        classes = classify_terms(pseudocode)
        lines = line_count(pseudocode)
        string_terms = [t for t in terms if t.startswith('"') or re.match(r"a[A-Z]", t)]

        if not string_terms:
            continue
        if not log_calls and traps == 0:
            continue

        score = len(string_terms) * 3 + log_calls * 6 + traps * 5 + calls - max(0, branches - 3) * 3
        risk = "low" if branches <= 3 and lines <= 80 else "medium" if branches <= 12 and lines <= 180 else "high"
        recommendation = "summary_candidate" if risk in {"low", "medium"} and classes else "review_only"
        rows.append(
            {
                "case_id": case_id,
                "stage_id": "S08",
                "iteration_id": "S08-DIAGNOSTIC-CANDIDATE-RW1",
                "generated_at": now_iso(),
                "address": addr,
                "ida_name": fn.get("ida_name"),
                "source_symbol": fn.get("source_symbol"),
                "source_file": fn.get("source_file"),
                "module": fn.get("module"),
                "output_class": fn.get("output_class"),
                "score": score,
                "risk": risk,
                "recommendation": recommendation,
                "behavior_classes": classes,
                "evidence_terms": terms,
                "metrics": {
                    "lines": lines,
                    "log_calls": log_calls,
                    "calls": calls,
                    "branches": branches,
                    "traps": traps,
                    "string_terms": len(string_terms),
                },
                "boundary": "Read-only candidate; do not promote without an explicit rewrite body and S09 consistency pass.",
            }
        )

    rows.sort(key=lambda r: (r["recommendation"] != "summary_candidate", r["risk"], -r["score"], r["address"]))
    rows = rows[:limit]
    out = s08 / "diagnostic-summary-candidates.jsonl"
    write_jsonl(out, rows)
    counts = Counter(row["risk"] for row in rows)
    classes = Counter(cls for row in rows for cls in row["behavior_classes"])
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-DIAGNOSTIC-CANDIDATE-RW1",
        "generated_at": now_iso(),
        "source_file": source_file or "all",
        "candidate_count": len(rows),
        "risk_counts": dict(counts),
        "behavior_class_counts": dict(classes),
        "top_candidates": [
            {
                "address": row["address"],
                "source_symbol": row["source_symbol"],
                "risk": row["risk"],
                "score": row["score"],
                "behavior_classes": row["behavior_classes"],
                "evidence_terms": row["evidence_terms"][:5],
            }
            for row in rows[:10]
        ],
        "boundary": "This file is planning evidence only; applied rewrites must be recorded separately.",
    }
    write_json(s08 / "diagnostic-summary-candidates-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--source-file")
    ap.add_argument("--limit", type=int, default=100)
    args = ap.parse_args()
    print(json.dumps(propose(args.case_id, args.source_file, args.limit), ensure_ascii=False))


if __name__ == "__main__":
    main()
