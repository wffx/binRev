#!/usr/bin/env python3
"""Annotate visible base+offset accesses with S06 candidate field names.

This is a presentation pass. It does not replace expressions or promote source
classes; it appends comments such as:

  *(_QWORD *)(a1 + 24) /* candidate_runtime_a1_object.field_0x18 */

The original Hex-Rays expression remains visible and traceable.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
ANNOTATION_RE = re.compile(r"\s*/\*\s*candidate_[A-Za-z0-9_]+\.field_0x[0-9a-fA-F]+\s*\*/")


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def load_struct_index(s06: Path) -> dict[tuple[str, str, int], str]:
    index: dict[tuple[str, str, int], str] = {}
    for st in read_jsonl(s06 / "struct-layouts.jsonl"):
        source = st.get("source_file")
        base = st.get("base")
        name = st.get("name")
        if not source or not base or not name:
            continue
        for field in st.get("fields", []):
            index[(source, base, int(field["offset"]))] = f"{name}.field_0x{int(field['offset']):x}"
    return index


def parse_offset(value: str) -> int:
    return int(value, 16) if value.lower().startswith("0x") else int(value)


def ignored_code_spans(text: str) -> list[tuple[int, int]]:
    """Return string/comment spans where source annotations must not be added.

    The lifted corpus contains inline Hex-Rays review strings and old evidence
    comments. Annotating inside those regions is actively harmful because it
    makes the user-facing source look more, not less, decompiler-like.
    """

    spans: list[tuple[int, int]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            start = i
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            spans.append((start, i))
            continue
        if ch == "/" and nxt == "*":
            start = i
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i = min(i + 2, n)
            spans.append((start, i))
            continue
        if ch in ('"', "'"):
            quote = ch
            start = i
            i += 1
            escaped = False
            while i < n:
                cur = text[i]
                if escaped:
                    escaped = False
                elif cur == "\\":
                    escaped = True
                elif cur == quote:
                    i += 1
                    break
                i += 1
            spans.append((start, i))
            continue
        i += 1
    return spans


def in_spans(offset: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= offset < end for start, end in spans)


def annotate_file(path: Path, rel: str, index: dict[tuple[str, str, int], str], max_annotations: int) -> tuple[int, list[dict[str, Any]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    text = ANNOTATION_RE.sub("", text)
    ignored = ignored_code_spans(text)
    rows: list[dict[str, Any]] = []
    count = 0
    pattern = re.compile(
        r"(?P<expr>\*\((?P<type>[^)]*\*)\)\((?P<base>[aA]\d)\s*\+\s*(?P<off>0x[0-9A-Fa-f]+|\d+)(?:LL?)?\))"
    )

    def repl(m: re.Match[str]) -> str:
        nonlocal count
        if count >= max_annotations:
            return m.group(0)
        if in_spans(m.start(), ignored):
            return m.group(0)
        end = m.end()
        if ANNOTATION_RE.match(text[end : end + 128]):
            return m.group(0)
        base = m.group("base").lower()
        off = parse_offset(m.group("off"))
        candidate = index.get((rel, base, off))
        if not candidate:
            return m.group(0)
        count += 1
        rows.append(
            {
                "source_file": rel,
                "base": base,
                "offset": off,
                "candidate": candidate,
                "expression": m.group("expr"),
            }
        )
        return f"{m.group('expr')} /* {candidate} */"

    new_text = pattern.sub(repl, text)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8", newline="\n")
    return count, rows


def annotate(case_id: str, max_annotations: int) -> dict[str, Any]:
    case = ROOT / "cases" / case_id
    s06 = case / "stages" / "S06"
    s08 = case / "stages" / "S08"
    repo = ROOT / "recovered-repos" / case_id / "recovered-hypervisor"
    index = load_struct_index(s06)

    all_rows: list[dict[str, Any]] = []
    file_counts: dict[str, int] = {}
    remaining = max_annotations
    for path in sorted(repo.rglob("*.c")):
        if remaining <= 0:
            break
        rel = path.relative_to(repo).as_posix()
        count, rows = annotate_file(path, rel, index, remaining)
        if count:
            file_counts[rel] = count
            all_rows.extend(rows)
            remaining -= count

    for row in all_rows:
        row.update(
            {
                "case_id": case_id,
                "stage_id": "S08",
                "iteration_id": "S08-OFFSET-FIELD-ANNOTATE-RW1",
                "generated_at": now_iso(),
                "boundary": "presentation annotation only; original expression remains unchanged",
            }
        )
    write_jsonl(s08 / "offset-field-annotation-index.jsonl", all_rows)
    summary = {
        "case_id": case_id,
        "stage_id": "S08",
        "iteration_id": "S08-OFFSET-FIELD-ANNOTATE-RW1",
        "requested_max": max_annotations,
        "annotated": len(all_rows),
        "file_counts": file_counts,
        "boundary": "Presentation annotations only. They do not confirm structure ownership or promote output_class.",
    }
    write_json(s08 / "offset-field-annotation-summary.json", summary)
    return summary


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--case-id", required=True)
    ap.add_argument("--max-annotations", type=int, default=2000)
    args = ap.parse_args()
    print(json.dumps(annotate(args.case_id, args.max_annotations), ensure_ascii=False))


if __name__ == "__main__":
    main()
