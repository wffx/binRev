"""Prototype IDA snapshot/export and transactional change application.

Run from IDA:
    idat64 -A -S"scripts/ida/hvrev_ida_bridge.py export snapshot.json" target.i64
    idat64 -A -S"scripts/ida/hvrev_ida_bridge.py apply actions.json result.json" target.i64

The script intentionally uses a small stable action vocabulary so analysis
changes can be reviewed and applied transactionally inside IDA.
"""

from __future__ import annotations

import json
import sys
import traceback

import ida_bytes
import ida_funcs
import ida_gdl
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_loader
import ida_name
import ida_segment
import ida_typeinf
import ida_ua
import idautils
import idc

try:
    import ida_hexrays
except ImportError:
    ida_hexrays = None


def _ea(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def _hex(value):
    return "0x%x" % value


def _segments():
    values = []
    for ea in idautils.Segments():
        segment = ida_segment.getseg(ea)
        values.append(
            {
                "name": ida_segment.get_segm_name(segment),
                "start": segment.start_ea,
                "start_hex": _hex(segment.start_ea),
                "end": segment.end_ea,
                "end_hex": _hex(segment.end_ea),
                "perm": segment.perm,
                "bitness": segment.bitness,
            }
        )
    return values


def _decompile(ea):
    if ida_hexrays is None or not ida_hexrays.init_hexrays_plugin():
        return None
    try:
        return str(ida_hexrays.decompile(ea))
    except ida_hexrays.DecompilationFailure:
        return None


def _function(function_ea):
    function = ida_funcs.get_func(function_ea)
    if not function:
        return None
    blocks = []
    for block in ida_gdl.FlowChart(function):
        successors = [item.start_ea for item in block.succs()]
        blocks.append(
            {
                "start": block.start_ea,
                "end": block.end_ea,
                "successors": successors,
            }
        )
    xrefs_from = []
    for item_ea in idautils.FuncItems(function.start_ea):
        for ref in idautils.XrefsFrom(item_ea, 0):
            xrefs_from.append(
                {"from": item_ea, "to": ref.to, "type": ref.type, "is_code": ref.iscode}
            )
    return {
        "address": function.start_ea,
        "address_hex": _hex(function.start_ea),
        "end": function.end_ea,
        "name": ida_name.get_name(function.start_ea),
        "prototype": idc.get_type(function.start_ea),
        "comment": ida_funcs.get_func_cmt(function, False),
        "blocks": blocks,
        "xrefs_from": xrefs_from,
        "pseudocode": _decompile(function.start_ea),
    }


def export_snapshot(path):
    functions = []
    for function_ea in idautils.Functions():
        value = _function(function_ea)
        if value:
            functions.append(value)
    snapshot = {
        "schema_version": 1,
        "ida": {
            "version": ida_kernwin.get_kernel_version(),
            "processor": ida_ida.inf_get_procname(),
            "is_64bit": ida_ida.inf_is_64bit(),
            "min_ea": ida_ida.inf_get_min_ea(),
            "max_ea": ida_ida.inf_get_max_ea(),
        },
        "segments": _segments(),
        "functions": functions,
    }
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(snapshot, stream, indent=2)
    return {"ok": True, "functions": len(functions), "output": path}


def _apply_one(action):
    kind = action["action"]
    ea = _ea(action["address"])
    before = {
        "name": ida_name.get_name(ea),
        "comment": idc.get_cmt(ea, 0),
        "type": idc.get_type(ea),
        "is_function": ida_funcs.get_func(ea) is not None,
    }
    if kind == "create_function":
        ok = ida_funcs.add_func(ea, _ea(action["end"]) if action.get("end") else ida_idaapi.BADADDR)
    elif kind == "rename":
        ok = ida_name.set_name(ea, action["name"], ida_name.SN_FORCE)
    elif kind == "comment":
        ok = idc.set_cmt(ea, action["comment"], int(action.get("repeatable", False)))
    elif kind == "function_comment":
        function = ida_funcs.get_func(ea)
        ok = bool(function) and ida_funcs.set_func_cmt(
            function, action["comment"], bool(action.get("repeatable", False))
        )
    elif kind == "apply_type":
        type_info = ida_typeinf.tinfo_t()
        ok = ida_typeinf.parse_decl(type_info, None, action["declaration"], 0)
        if ok:
            ok = ida_typeinf.apply_tinfo(ea, type_info, ida_typeinf.TINFO_DEFINITE)
    elif kind == "make_code":
        ok = ida_ua.create_insn(ea) > 0
    else:
        raise ValueError("unsupported action: %s" % kind)
    return {"action": action, "ok": bool(ok), "before": before}


def apply_actions(actions_path, result_path):
    with open(actions_path, "r", encoding="utf-8") as stream:
        document = json.load(stream)
    results = []
    for action in document.get("actions", []):
        try:
            results.append(_apply_one(action))
        except Exception as error:
            results.append(
                {
                    "action": action,
                    "ok": False,
                    "error": str(error),
                    "traceback": traceback.format_exc(),
                }
            )
    ida_loader.save_database(
        ida_loader.get_path(ida_loader.PATH_TYPE_IDB), ida_loader.DBFL_BAK
    )
    output = {
        "schema_version": 1,
        "transaction": document.get("transaction"),
        "results": results,
        "ok": all(item["ok"] for item in results),
    }
    with open(result_path, "w", encoding="utf-8") as stream:
        json.dump(output, stream, indent=2)
    return output


def main(argv):
    if len(argv) < 3:
        raise SystemExit("usage: hvrev_ida_bridge.py export OUT | apply ACTIONS OUT")
    command = argv[1]
    if command == "export":
        result = export_snapshot(argv[2])
    elif command == "apply" and len(argv) >= 4:
        result = apply_actions(argv[2], argv[3])
    else:
        raise SystemExit("invalid command")
    print(json.dumps(result))
    idc.qexit(0 if result.get("ok") else 2)


if __name__ == "__main__":
    # IDA provides script arguments through idc.ARGV.
    main(idc.ARGV if hasattr(idc, "ARGV") else sys.argv)
