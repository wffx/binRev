"""
export_functions_with_context.py

Reusable IDAPython script for S02 function export with context frame analysis.

Extends the basic function export with stack frame and register save/restore
information, providing direct input for S03 context-layout analysis.

Usage (IDAPython):
    exec(open("export_functions_with_context.py").read())

Output:
    Structured function data including frame size, saved/restored registers,
    and STP/LDP offset patterns for context layout recovery.
"""

import idc
import idautils
import ida_funcs
import re
import json
from collections import defaultdict


def extract_stack_frame(func_ea, func_end):
    """
    Scan function prologue (first 0x100 bytes) for STP/LDP patterns.
    Returns dict with frame_size, saved_regs, context_offsets.
    """
    result = {
        "frame_size": 0,
        "saved_regs": [],
        "restored_regs": [],
        "context_offsets": {}  # offset -> {"stp": count, "ldp": count, "regs": set()}
    }
    
    for head in idautils.Heads(func_ea, min(func_ea + 0x200, func_end)):
        mnem = idc.print_insn_mnem(head)
        if mnem not in ('STP', 'LDP'):
            continue
        
        line = idc.GetDisasm(head)
        if 'SP' not in line:
            continue
        
        # Extract offset from var_XXX pattern
        m = re.search(r'var_([0-9A-Fa-f]+)', line)
        if not m:
            continue
        
        offset = int(m.group(1), 16)
        if offset < 0x8:
            continue
        
        reg0 = idc.print_operand(head, 0)
        reg1 = idc.print_operand(head, 1)
        
        if offset > result["frame_size"]:
            result["frame_size"] = offset
        
        if mnem == 'STP':
            result["saved_regs"].append(reg0)
            result["saved_regs"].append(reg1)
        else:
            result["restored_regs"].append(reg0)
            result["restored_regs"].append(reg1)
        
        off_key = f"sp_{offset:X}"
        if off_key not in result["context_offsets"]:
            result["context_offsets"][off_key] = {"stp": 0, "ldp": 0, "regs": set()}
        
        entry = result["context_offsets"][off_key]
        if mnem == 'STP':
            entry["stp"] += 1
        else:
            entry["ldp"] += 1
        entry["regs"].add(reg0)
        entry["regs"].add(reg1)
    
    # Convert sets to lists for JSON
    for key in result["context_offsets"]:
        result["context_offsets"][key]["regs"] = list(result["context_offsets"][key]["regs"])
    
    return result


def export_all_functions():
    """
    Export all IDA functions with call graph edges and context frame data.
    Returns (functions_list, edges_list).
    """
    functions = []
    edges = []
    
    for func_ea in idautils.Functions():
        func = ida_funcs.get_func(func_ea)
        if not func:
            continue
        
        name = idc.get_name(func_ea)
        size = func.end_ea - func.start_ea
        
        callees = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            mnem = idc.print_insn_mnem(head)
            if mnem in ('BL', 'B'):
                target = idc.get_operand_value(head, 0)
                if target != 0xFFFFFFFFFFFFFFFF:
                    tf = ida_funcs.get_func(target)
                    if tf and tf.start_ea != func_ea:
                        callees.append(tf.start_ea)
                        edges.append({"from": func_ea, "to": tf.start_ea})
        
        # Extract context frame data
        try:
            ctx = extract_stack_frame(func_ea, func.end_ea)
        except:
            ctx = {"frame_size": 0, "saved_regs": [], "restored_regs": [], "context_offsets": {}}
        
        functions.append({
            "address": func_ea,
            "name": name,
            "size": size,
            "confidence": "candidate",
            "boundary_status": "ida_auto",
            "callees": callees,
            "frame_size": ctx["frame_size"],
            "saved_regs": ctx["saved_regs"][:8],      # first 8 unique
            "restored_regs": ctx["restored_regs"][:8],  # first 8 unique
            "has_context_frame": ctx["frame_size"] >= 0x10
        })
    
    return functions, edges


if __name__ == "__main__":
    funcs, edges = export_all_functions()
    print(f"FUNCTIONS_COUNT: {len(funcs)}")
    print(f"EDGES_COUNT: {len(edges)}")
    print("FUNC_JSON:", json.dumps(funcs, default=str))
    print("EDGE_JSON:", json.dumps(edges, default=str))
