
# -*- coding: utf-8 -*-
# NGS2 RUN 2 - Parameter and callback investigation
# IDA 7.x / IDAPython / Python 2.7
#
# Output:
#   run2_parameter_hits.json
#   run2_target_functions.json
#   run2_data_refs.json
#   run2_listing.asm.txt
#
# No binary modifications.

from __future__ import print_function

import os
import re
import json
import time
import codecs
import collections

import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_kernwin
import ida_bytes

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

TARGETS = [
    0x1AC510,
    0x1A9690,
    0x1ADC10,
    0x1AEFD0,
    0x1AB580,
    0x1B2010,
]

# Investigate these values without assuming semantics.
PARAMS = {
    0x40001C00: "PS4_CHORUS",
    0x40001D00: "PS4_DELAY_OR_PS5_USER_FX",
    0x40002000: "UNKNOWN_CUSTOM_PARAM",
    0x20000005: "UNKNOWN_SUBMIXER_PARAM",
    0x10000008: "SAMPLER_USER_FX",
    0x10000009: "SAMPLER_PEAK_METER",
    0x20000004: "SUBMIXER_USER_FX",
    0x30000003: "MASTERING_LIMITER",
    0x30000004: "MASTERING_GAIN",
    0x40020000: "CUSTOM_SETUP",
    0x10000007: "SAMPLER_UNKNOWN_7",
    0x10000003: "SAMPLER_UNKNOWN_3",
}

PARAMS64 = {
    0x0000000140001C00: "64_PS4_CHORUS",
    0x0000000140001D00: "64_PS4_DELAY",
    0x0000000140002000: "64_UNKNOWN_CUSTOM",
    0x0000000120000005: "64_UNKNOWN_SUBMIXER",
    0x0000000110000008: "64_SAMPLER_USER_FX",
    0x0000000110000009: "64_SAMPLER_PEAK",
}

# Include relevant Sony audio APIs and callback-related functions.
API_PATTERNS = [
    "sceNgs2VoiceControl",
    "sceNgs2RackCreate",
    "sceNgs2RackQueryBufferSize",
    "sceNgs2RackGetVoiceHandle",
    "sceAudio3dObjectSetAttributes",
]

CONTEXT_BEFORE = 24
CONTEXT_AFTER = 8

MAX_DATA_DUMP = 0x100
MAX_DATA_REFS_PER_FUNCTION = 10000


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

def hx(v):
    try:
        return "0x%X" % (long(v) & 0xFFFFFFFFFFFFFFFF)
    except:
        return str(v)


def get_name(ea):
    try:
        return ida_name.get_name(ea) or idc.get_func_name(ea) or ""
    except:
        return ""


def get_func(ea):
    try:
        return ida_funcs.get_func(ea)
    except:
        return None


def get_bounds(f):
    try:
        return f.start_ea, f.end_ea
    except:
        return f.startEA, f.endEA


def insn(ea):
    try:
        return idc.generate_disasm_line(ea, 0) or ""
    except:
        return idc.GetDisasm(ea) or ""


def mnem(ea):
    try:
        return idc.print_insn_mnem(ea).lower()
    except:
        return ""


def read_u32(ea):
    try:
        return long(ida_bytes.get_dword(ea))
    except:
        try:
            return long(idc.Dword(ea))
        except:
            return None


def read_bytes(ea, size):
    try:
        return ida_bytes.get_bytes(ea, size)
    except:
        try:
            return idc.get_bytes(ea, size)
        except:
            return None


def save_json(path, data):
    with codecs.open(path, "w", "utf-8") as fp:
        fp.write(json.dumps(
            data,
            indent=2,
            sort_keys=True,
            ensure_ascii=True
        ))


def get_operand_value(ea, op):
    try:
        if idc.get_operand_type(ea, op) == idc.o_imm:
            return long(idc.get_operand_value(ea, op))
    except:
        pass
    return None


def get_operands(ea):
    result = []

    for op in range(8):
        try:
            typ = idc.get_operand_type(ea, op)
            txt = idc.print_operand(ea, op)

            if not txt:
                continue

            item = {
                "index": op,
                "type": typ,
                "text": txt,
            }

            value = get_operand_value(ea, op)

            if value is not None:
                item["value"] = hx(value)

                low = value & 0xFFFFFFFF

                if value in PARAMS64:
                    item["match"] = PARAMS64[value]
                elif low in PARAMS:
                    item["match"] = PARAMS[low]

            result.append(item)

        except:
            pass

    return result


def instruction(ea):
    return {
        "ea": hx(ea),
        "mnemonic": mnem(ea),
        "text": insn(ea),
        "operands": get_operands(ea),
    }


def get_function_instructions(f):
    start, end = get_bounds(f)
    return list(idautils.Heads(start, end))


def get_context(ea, f):
    start, end = get_bounds(f)
    heads = get_function_instructions(f)

    try:
        index = heads.index(ea)
    except:
        index = 0

    first = max(0, index - CONTEXT_BEFORE)
    last = min(len(heads), index + CONTEXT_AFTER + 1)

    return [
        instruction(x)
        for x in heads[first:last]
    ]


# ------------------------------------------------------------
# 1. Global immediate search
# ------------------------------------------------------------

def scan_immediates():
    hits = collections.defaultdict(list)
    functions = list(idautils.Functions())

    for fi, fea in enumerate(functions):
        f = get_func(fea)

        if not f:
            continue

        start, end = get_bounds(f)

        for ea in idautils.Heads(start, end):
            for op in range(8):
                value = get_operand_value(ea, op)

                if value is None:
                    continue

                value &= 0xFFFFFFFFFFFFFFFF

                name = None

                if value in PARAMS64:
                    name = PARAMS64[value]
                elif (value & 0xFFFFFFFF) in PARAMS:
                    name = PARAMS[value & 0xFFFFFFFF]

                if name is None:
                    continue

                key = hx(value)

                hits[key].append({
                    "name": name,
                    "ea": hx(ea),
                    "function": get_name(fea),
                    "function_start": hx(fea),
                    "operand": op,
                    "instruction": insn(ea),
                })

        if fi % 250 == 0:
            pct = 5 + int(
                20.0 * (fi + 1) / max(1, len(functions))
            )

            msg = "[RUN2 %d%%] Immediate scan %d/%d" % (
                pct, fi + 1, len(functions)
            )

            print(msg)

            try:
                ida_kernwin.replace_wait_box(msg)
            except:
                pass

    return dict(hits), len(functions)


# ------------------------------------------------------------
# 2. Search references to parameter values in data
# ------------------------------------------------------------

def scan_data_words():
    result = collections.defaultdict(list)

    min_ea = idaapi.get_imagebase()
    max_ea = idaapi.BADADDR

    try:
        max_ea = idaapi.get_inf_structure().max_ea
    except:
        pass

    for value, name in PARAMS.items():
        current = min_ea

        while current != idaapi.BADADDR:
            ea = ida_bytes.find_binary(
                current,
                max_ea,
                "%02X %02X %02X %02X" % (
                    value & 0xFF,
                    (value >> 8) & 0xFF,
                    (value >> 16) & 0xFF,
                    (value >> 24) & 0xFF
                ),
                16,
                ida_bytes.BIN_SEARCH_FORWARD
            )

            if ea == idaapi.BADADDR:
                break

            result[hx(value)].append({
                "name": name,
                "ea": hx(ea),
                "segment": idc.get_segm_name(ea),
                "is_code": bool(
                    ida_bytes.is_code(
                        ida_bytes.get_full_flags(ea)
                    )
                ),
            })

            current = ea + 1

    return dict(result)


# ------------------------------------------------------------
# 3. Analyze target functions and their callers
# ------------------------------------------------------------

def analyze_function(ea):
    f = get_func(ea)

    if not f:
        return {
            "requested": hx(ea),
            "found": False,
        }

    start, end = get_bounds(f)

    instructions = get_function_instructions(f)

    rows = [
        instruction(x)
        for x in instructions
    ]

    callers = []

    for x in idautils.XrefsTo(start, 0):
        src = x.frm
        caller = get_func(src)

        if caller:
            cs, ce = get_bounds(caller)
            caller_name = get_name(cs)
        else:
            cs = None
            caller_name = ""

        callers.append({
            "ea": hx(src),
            "function": caller_name,
            "function_start": hx(cs) if cs is not None else None,
            "instruction": insn(src),
        })

    return {
        "requested": hx(ea),
        "found": True,
        "name": get_name(start),
        "start": hx(start),
        "end": hx(end),
        "size": end - start,
        "callers": callers,
        "instructions": rows,
    }


# ------------------------------------------------------------
# 4. Find all references to target API names
# ------------------------------------------------------------

def find_api_addresses():
    result = collections.defaultdict(set)

    for ea, name in idautils.Names():
        for pattern in API_PATTERNS:
            if pattern.lower() in name.lower():
                result[pattern].add(ea)

    for ea in idautils.Functions():
        name = get_name(ea)

        for pattern in API_PATTERNS:
            if pattern.lower() in name.lower():
                result[pattern].add(ea)

    return result


def analyze_api_calls():
    imports = find_api_addresses()
    result = []

    for api, addresses in imports.items():
        for target in addresses:
            for x in idautils.XrefsTo(target, 0):
                ea = x.frm
                f = get_func(ea)

                if f:
                    fs, fe = get_bounds(f)
                else:
                    fs = None

                result.append({
                    "api": api,
                    "target": hx(target),
                    "callsite": hx(ea),
                    "function": get_name(fs) if fs is not None else "",
                    "function_start": hx(fs) if fs is not None else None,
                    "instruction": insn(ea),
                    "context": get_context(ea, f) if f else [],
                })

    return result


# ------------------------------------------------------------
# 5. Search data xrefs from target functions
# ------------------------------------------------------------

def analyze_data_refs():
    result = []

    for fea in TARGETS:
        f = get_func(fea)

        if not f:
            continue

        start, end = get_bounds(f)
        count = 0

        for ea in idautils.Heads(start, end):
            for target in idautils.DataRefsFrom(ea):
                count += 1

                if count > MAX_DATA_REFS_PER_FUNCTION:
                    break

                size = min(MAX_DATA_DUMP, 0x40)
                raw = read_bytes(target, size)

                if raw is not None:
                    hexdata = " ".join(
                        "%02X" % ord(c) for c in raw
                    )
                else:
                    hexdata = None

                result.append({
                    "function": get_name(start),
                    "instruction": hx(ea),
                    "instruction_text": insn(ea),
                    "target": hx(target),
                    "target_name": get_name(target),
                    "data_preview": hexdata,
                })

    return result


# ------------------------------------------------------------
# 6. Extract all instructions with VoiceControl
# ------------------------------------------------------------

def voice_control_sites():
    result = []

    for fea in idautils.Functions():
        f = get_func(fea)

        if not f:
            continue

        start, end = get_bounds(f)

        for ea in idautils.Heads(start, end):
            text = insn(ea)

            if "sceNgs2VoiceControl" not in text:
                continue

            result.append({
                "function": get_name(start),
                "function_start": hx(start),
                "callsite": hx(ea),
                "instruction": text,
                "context": get_context(ea, f),
            })

    return result


# ------------------------------------------------------------
# 7. Assembly listing
# ------------------------------------------------------------

def write_listing(path):
    with codecs.open(path, "w", "utf-8") as fp:
        fp.write("NGS2 RUN2 TARGET LISTING\n")

        for ea in TARGETS:
            f = get_func(ea)

            fp.write("\n====================================\n")

            if not f:
                fp.write("NOT FOUND: %s\n" % hx(ea))
                continue

            start, end = get_bounds(f)

            fp.write(
                "%s %s - %s\n" %
                (get_name(start), hx(start), hx(end))
            )

            for addr in idautils.Heads(start, end):
                fp.write(
                    "%s  %s\n" %
                    (hx(addr), insn(addr))
                )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main():
    selected = ida_kernwin.ask_file(
        True,
        "*.json",
        "Save NGS2 RUN2 report prefix"
    )

    if not selected:
        return

    root = os.path.splitext(selected)[0]

    ida_kernwin.show_wait_box(
        "NGS2 RUN2 targeted investigation..."
    )

    started = time.time()

    try:
        print("[RUN2 5%] Scanning immediate values")

        immediate_hits, function_count = scan_immediates()

        save_json(root + "_parameter_hits.json", {
            "functions_scanned": function_count,
            "hits": immediate_hits,
        })

        print("[RUN2 30%] Searching data words")

        data_words = scan_data_words()

        save_json(root + "_data_words.json", {
            "hits": data_words,
        })

        print("[RUN2 45%] Analyzing target functions")

        target_results = {}

        for ea in TARGETS:
            target_results[hx(ea)] = analyze_function(ea)

        save_json(root + "_target_functions.json", {
            "targets": target_results,
        })

        print("[RUN2 65%] Analyzing API calls")

        api_results = analyze_api_calls()

        voice_sites = voice_control_sites()

        save_json(root + "_api_calls.json", {
            "api_calls": api_results,
            "voice_control_sites": voice_sites,
        })

        print("[RUN2 80%] Analyzing data references")

        data_refs = analyze_data_refs()

        save_json(root + "_data_refs.json", {
            "references": data_refs,
        })

        print("[RUN2 95%] Writing assembly")

        write_listing(root + "_listing.asm.txt")

        print("[RUN2 100%] Complete")

        files = [
            "_parameter_hits.json",
            "_data_words.json",
            "_target_functions.json",
            "_api_calls.json",
            "_data_refs.json",
            "_listing.asm.txt",
        ]

        message = "RUN2 completed\n\n"

        for suffix in files:
            path = root + suffix

            try:
                message += "%s: %.2f MB\n" % (
                    os.path.basename(path),
                    os.path.getsize(path) / 1048576.0
                )
            except:
                message += os.path.basename(path) + "\n"

        message += "\nElapsed: %.1f sec" % (
            time.time() - started
        )

        print(message)
        ida_kernwin.info(message)

    finally:
        ida_kernwin.hide_wait_box()


try:
    main()
except Exception as e:
    print("[RUN2 ERROR] %s" % str(e))
    raise
