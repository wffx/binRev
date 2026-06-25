"""IDA headless helper for S05 Stage-2 owner/root matching.

Run inside IDA/IDAT. Configure with environment variables:

- BINREV_ROOT: repository root, default current working directory
- CASE_ID: case directory name under cases/
- SETUP_FUNCS: comma-separated setup function starts, e.g. 0x5d2e0,0x5a294
- TEARDOWN_SCAN: JSON path relative to S05 stage dir or absolute
- WATCH_OFFSETS: comma-separated field offsets, default S05 lifecycle offsets
- OUT_NAME: output JSON name, default s05-owner-root-match.json

This script is intentionally conservative: exact root-signature matches and weak
offset/field-family matches are separated so downstream skills cannot promote
weak matches into production ownership links by accident.
"""

import json
import os
import re

import ida_funcs
import ida_lines
import idautils
import idc


DEFAULT_OFFSETS = "0x18,0x20,0x28,0x41,0x338,0x340,0x348,0x350,0x388"
REG = r"(?:[WX][0-9]+|SP|XZR|WZR)"


def parse_hex_list(value):
    out = []
    for part in (value or "").split(","):
        part = part.strip()
        if part:
            out.append(int(part, 16))
    return out


def repo_root():
    return os.environ.get("BINREV_ROOT") or os.getcwd()


def stage_dir():
    case_id = os.environ["CASE_ID"]
    return os.path.join(repo_root(), "cases", case_id, "stages", "S05")


def hx(ea):
    if ea is None or ea == idc.BADADDR:
        return None
    return "0x%x" % ea


def clean(ea):
    return ida_lines.tag_remove(idc.generate_disasm_line(ea, 0) or "")


def func_info(ea):
    f = ida_funcs.get_func(ea)
    if not f:
        return {"start": hx(ea), "end": None, "name": idc.get_name(ea) or None}
    return {"start": hx(f.start_ea), "end": hx(f.end_ea), "name": idc.get_func_name(f.start_ea)}


def insns_in_func(start):
    f = ida_funcs.get_func(start)
    if not f:
        return []
    return list(idautils.FuncItems(f.start_ea))


def writes_reg(text):
    m = re.match(r"\s*[A-Z0-9.]+\s+(" + REG + r")\b", text)
    return m.group(1).upper() if m else None


def source_regs(text):
    return [r.upper() for r in re.findall(r"\b" + REG + r"\b", text)[1:]]


def classify_root(text):
    if "ADRP" in text or "@PAGE" in text:
        return "address_literal"
    if re.search(r"\bLDR\b|\bLDUR\b|\bLDP\b", text):
        if "[SP" in text:
            return "stack_reload"
        return "memory_load"
    if "MRS" in text:
        return "sysreg"
    if re.search(r"\bADD\b|\bSUB\b|\bMOV\b|\bUBF|LSL|LSR", text):
        return "compute"
    return "other"


def root_signature(item):
    names = item.get("names") or []
    if names:
        return item["class"] + ":" + "|".join(names)
    return item["class"] + ":" + item.get("text", "")


def trace_reg_back(func_start, ea, reg, limit=64):
    reg = reg.upper()
    items = [x for x in insns_in_func(func_start) if x < ea]
    trace = []
    roots = []
    steps = 0
    for cur in reversed(items):
        if steps >= limit:
            break
        text = clean(cur)
        dst = writes_reg(text)
        if dst != reg:
            continue
        cls = classify_root(text)
        names = []
        for opnum in range(3):
            name = idc.get_name(idc.get_operand_value(cur, opnum))
            if name:
                names.append(name)
        item = {
            "ea": hx(cur),
            "text": text,
            "class": cls,
            "writes": [dst],
            "source_regs": source_regs(text),
            "names": names,
        }
        trace.append(item)
        if cls in ("address_literal", "memory_load", "stack_reload", "sysreg"):
            roots.append(item)
        srcs = [r for r in item["source_regs"] if r != reg and not r.endswith("ZR")]
        if srcs:
            reg = srcs[0]
        else:
            break
        steps += 1
    roots = list(reversed(roots))
    trace = list(reversed(trace))
    return {"roots": roots, "trace": trace}


def field_family(offset):
    if offset in (0x18, 0x20, 0x28):
        return "switch_or_stage2_source_fields"
    if offset in (0x338, 0x340, 0x348, 0x350, 0x388):
        return "lifecycle_preparation_fields"
    if offset == 0x41:
        return "state_flag_clear"
    return "other"


def collect_store_records(func_start, offsets, mode):
    rows = []
    for ea in insns_in_func(func_start):
        text = clean(ea)
        m = re.search(r"\[(" + REG + r"),#(0x[0-9A-Fa-f]+|\d+)\]", text)
        if not m:
            continue
        off = int(m.group(2), 0)
        if off not in offsets:
            continue
        if not re.search(r"\bSTR|STP|STUR\b", text):
            continue
        zero = bool(re.search(r"\bXZR\b|\bWZR\b", text))
        if mode == "teardown" and not zero:
            continue
        base = m.group(1).upper()
        rt = trace_reg_back(func_start, ea, base)
        root_sigs = [root_signature(x) for x in rt["roots"]]
        rows.append(
            {
                "mode": mode,
                "ea": hx(ea),
                "text": text,
                "base": base,
                "offset": hx(off),
                "field_family": field_family(off),
                "is_zero_store": zero,
                "root_trace": rt,
                "root_signatures": root_sigs,
                "last_root_signature": root_sigs[-1] if root_sigs else "none",
            }
        )
    return rows


def teardown_targets(scan_path):
    if not os.path.isabs(scan_path):
        scan_path = os.path.join(stage_dir(), scan_path)
    data = json.load(open(scan_path, "r", encoding="utf-8"))
    targets = []
    for row in data.get("teardown_candidates", []):
        start = row.get("function", {}).get("start")
        if start:
            targets.append(int(start, 16))
    for row in data.get("direct_s05_cleanup", []):
        start = row.get("function", {}).get("start")
        if start:
            targets.append(int(start, 16))
    return sorted(set(targets))


def score_pair(a, b):
    reasons = []
    score = 0
    common_sigs = sorted(set(a["root_signatures"]) & set(b["root_signatures"]))
    if common_sigs:
        score += 6
        reasons.append("common_root_signature")
    if a["last_root_signature"] != "none" and a["last_root_signature"] == b["last_root_signature"]:
        score += 4
        reasons.append("same_last_root")
    if a["offset"] == b["offset"]:
        score += 3
        reasons.append("same_offset")
    if a["field_family"] == b["field_family"]:
        score += 1
        reasons.append("same_lifecycle_field_family")
    exact = bool(common_sigs) or "same_last_root" in reasons
    weak = not exact and score > 0
    return score, reasons, common_sigs, exact, weak


def main():
    case_id = os.environ.get("CASE_ID")
    if not case_id:
        raise SystemExit("CASE_ID is required")
    setup_funcs = parse_hex_list(os.environ.get("SETUP_FUNCS"))
    if not setup_funcs:
        raise SystemExit("SETUP_FUNCS is required")
    offsets = set(parse_hex_list(os.environ.get("WATCH_OFFSETS", DEFAULT_OFFSETS)))
    scan_path = os.environ.get("TEARDOWN_SCAN", "s05-rw5-teardown-scan.json")
    out_name = os.environ.get("OUT_NAME", "s05-owner-root-match.json")
    out_path = os.path.join(stage_dir(), out_name)

    setup = []
    teardown = []
    for f in setup_funcs:
        for rec in collect_store_records(f, offsets, "setup"):
            setup.append({"function": func_info(f), "record": rec})
    for f in teardown_targets(scan_path):
        for rec in collect_store_records(f, offsets, "teardown"):
            teardown.append({"function": func_info(f), "record": rec})

    exact_matches = []
    weak_matches = []
    for a in setup:
        for b in teardown:
            score, reasons, common_sigs, exact, weak = score_pair(a["record"], b["record"])
            if score <= 0:
                continue
            row = {
                "score": score,
                "reasons": reasons,
                "common_root_signatures": common_sigs,
                "setup_function": a["function"],
                "setup_record": a["record"],
                "teardown_function": b["function"],
                "teardown_record": b["record"],
            }
            if exact:
                exact_matches.append(row)
            elif weak:
                weak_matches.append(row)

    exact_matches.sort(key=lambda x: (-x["score"], x["setup_record"]["ea"]))
    weak_matches.sort(key=lambda x: (-x["score"], x["setup_record"]["ea"]))
    result = {
        "producer": "recover-hypervisor-stage2-memory-model/scripts/owner_root_match_ida.py",
        "case_id": case_id,
        "stage_id": "S05",
        "idb": idc.get_input_file_path(),
        "imagebase": hx(idc.get_inf_attr(idc.INF_MIN_EA)),
        "setup_functions": [hx(x) for x in setup_funcs],
        "teardown_scan": scan_path,
        "match_summary": {
            "setup_record_count": len(setup),
            "teardown_record_count": len(teardown),
            "exact_root_match_count": len(exact_matches),
            "weak_match_count": len(weak_matches),
            "match_count": len(exact_matches) + len(weak_matches),
        },
        "exact_root_matches": exact_matches,
        "weak_matches": weak_matches,
    }
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print("WROTE", out_path)


if __name__ == "__main__":
    main()
