
# -*- coding: utf-8 -*-
# NGS2 Static Mapper
# IDA 7.x / IDAPython / Python 2.7
#
# Запуск: File -> Script file...
#
# Output:
#   ngs2_map.json
#   ngs2_map.tsv

from __future__ import print_function

import idaapi
import idautils
import idc
import ida_funcs
import ida_name
import ida_kernwin

import os
import json
import time
import re
import collections

APIS = [
    "sceNgs2SystemCreateWithAllocator",
    "sceNgs2SystemRender",
    "sceNgs2SystemDestroy",
    "sceNgs2RackQueryBufferSize",
    "sceNgs2RackCreate",
    "sceNgs2RackCreateWithAllocator",
    "sceNgs2RackDestroy",
    "sceNgs2RackGetVoiceHandle",
    "sceNgs2VoiceControl",
    "sceNgs2VoiceGetState"
]

RACKS = {
    0x1000: "SAMPLER",
    0x2000: "SUBMIXER",
    0x2001: "REVERB",
    0x3000: "MASTERING",
    0x4002: "CUSTOM"
}

PARAMS = {
    0x00000001: "MATRIX_LEVELS",
    0x00000002: "PORT_VOLUME",
    0x00000003: "PORT_MATRIX",
    0x00000005: "PATCH",
    0x00000006: "KICK_EVENT",

    0x10000000: "SAMPLER_SETUP",
    0x10000001: "ADD_WAVEFORM_BLOCKS",
    0x10000005: "PITCH",
    0x10000006: "ENVELOPE",
    0x10000008: "USER_FX",
    0x10000009: "PEAK_METER",
    0x1000000A: "FILTER",

    0x20000000: "SUBMIXER_SETUP",
    0x20000002: "COMPRESSOR",
    0x20000004: "USER_FX",
    0x20000006: "FILTER",

    0x20010000: "REVERB_SETUP",
    0x20010001: "I3DL2",

    0x30000000: "MASTERING_SETUP",
    0x30000002: "LFE_FILTER",
    0x30000003: "LIMITER",
    0x30000004: "GAIN",
    0x30000005: "OUTPUT",

    0x40020000: "CUSTOM_SETUP",
    0x40001C00: "CHORUS",
    0x40001D00: "DELAY"
}

BACKTRACK = 30
PROGRESS = 0


def progress(value, message):
    global PROGRESS

    PROGRESS = value

    line = "[NGS2 %3d%%] %s" % (
        value, message
    )

    print(line)

    try:
        ida_kernwin.replace_wait_box(line)
    except:
        pass


def hx(value):
    return "0x%X" % value


def name(ea):
    return ida_name.get_name(ea) or idc.get_func_name(ea) or ""


def function(ea):
    return ida_funcs.get_func(ea)


def disasm(ea):
    try:
        return idc.GetDisasm(ea)
    except:
        return idc.generate_disasm_line(ea, 0) or ""


def mnemonic(ea):
    try:
        return idc.print_insn_mnem(ea).lower()
    except:
        return ""


def is_call(ea):
    return mnemonic(ea) in (
        "call", "callq", "bl", "blr"
    )


def func_bounds(f):
    return (
        getattr(f, "start_ea", f.startEA),
        getattr(f, "end_ea", f.endEA)
    )


def find_imports():

    result = collections.defaultdict(set)

    for ea, n in idautils.Names():

        for api in APIS:

            if api in n:
                result[api].add(ea)

    for ea in idautils.Functions():

        n = name(ea)

        for api in APIS:

            if api in n:
                result[api].add(ea)

    return result


def find_xrefs(imports):

    result = []

    for api, addresses in imports.items():

        for target in addresses:

            for xref in idautils.XrefsTo(target, 0):

                ea = xref.frm
                f = function(ea)

                if not f:
                    continue

                start, end = func_bounds(f)

                result.append({
                    "api": api,
                    "target": hx(target),
                    "call": hx(ea),
                    "function": name(start),
                    "function_ea": hx(start),
                    "is_call": is_call(ea),
                    "disasm": disasm(ea)
                })

    unique = {}

    for r in result:
        unique[(r["api"], r["call"])] = r

    return list(unique.values())


def context(ea, f):

    start, end = func_bounds(f)

    addresses = list(
        idautils.Heads(start, end)
    )

    try:
        index = addresses.index(ea)
    except:
        return []

    left = max(0, index - BACKTRACK)
    right = min(len(addresses), index + 6)

    result = []

    for addr in addresses[left:right]:

        result.append({
            "ea": hx(addr),
            "instruction": disasm(addr)
        })

    return result


def constants(f):

    start, end = func_bounds(f)

    result = []

    for ea in idautils.Heads(start, end):

        for op in range(4):

            try:
                if idc.get_operand_type(ea, op) != idc.o_imm:
                    continue

                value = idc.get_operand_value(ea, op)

            except:
                continue

            if value < 0 or value > 0xFFFFFFFF:
                continue

            label = None

            if value in RACKS:
                label = RACKS[value]

            elif value in PARAMS:
                label = PARAMS[value]

            elif value == 0xBB80:
                label = "48000_HZ"

            elif value == 0x100:
                label = "256_SAMPLES"

            elif value == 0x200:
                label = "512_SAMPLES"

            if label:

                result.append({
                    "ea": hx(ea),
                    "value": hx(value),
                    "label": label,
                    "instruction": disasm(ea)
                })

    return result


def argument_context(ea, f):

    ctx = context(ea, f)

    # x86-64 SysV argument registers.
    registers = [
        "rdi", "rsi", "rdx",
        "rcx", "r8", "r9"
    ]

    result = {}

    for reg in registers:

        matches = []

        for row in ctx:

            ins = row["instruction"]

            if re.search(
                r"\b" + reg + r"\b",
                ins,
                re.I
            ):
                matches.append({
                    "ea": row["ea"],
                    "instruction": ins
                })

        result[reg.upper()] = matches

    return result


def main():

    output = ida_kernwin.ask_file(
        True,
        "*.json",
        "Save NGS2 report"
    )

    if not output:
        return

    if not output.endswith(".json"):
        output += ".json"

    t0 = time.time()

    ida_kernwin.show_wait_box(
        "NGS2 static analysis..."
    )

    progress(5, "Finding NGS2 imports")

    imports = find_imports()

    progress(20, "Resolving cross references")

    calls = find_xrefs(imports)

    progress(40, "Analyzing caller functions")

    caller_addresses = sorted(set(
        r["function_ea"] for r in calls
    ))

    callers = []

    for i, addr in enumerate(caller_addresses):

        ea = int(addr, 16)
        f = function(ea)

        if not f:
            continue

        caller_calls = [
            r for r in calls
            if r["function_ea"] == addr
        ]

        callers.append({
            "name": name(ea),
            "address": addr,
            "apis": sorted(set(
                r["api"] for r in caller_calls
            )),
            "constants": constants(f),
            "calls": [
                {
                    "api": r["api"],
                    "address": r["call"],
                    "disasm": r["disasm"],
                    "context": context(
                        int(r["call"], 16), f
                    ),
                    "argument_context": argument_context(
                        int(r["call"], 16), f
                    )
                }
                for r in caller_calls
            ]
        })

        if i % 10 == 0:
            pct = 40 + int(
                25.0 * (i + 1) /
                max(1, len(caller_addresses))
            )

            progress(
                pct,
                "Caller analysis %d/%d" %
                (i + 1, len(caller_addresses))
            )

    progress(70, "Scanning all functions for NGS2 constants")

    global_constants = collections.defaultdict(list)

    functions = list(idautils.Functions())

    for i, ea in enumerate(functions):

        f = function(ea)

        if not f:
            continue

        for item in constants(f):

            key = item["value"]

            if len(global_constants[key]) < 100:

                global_constants[key].append({
                    "function": name(ea),
                    "instruction": item["instruction"],
                    "ea": item["ea"]
                })

        if i % 250 == 0:

            pct = 70 + int(
                10.0 * (i + 1) /
                max(1, len(functions))
            )

            progress(
                min(pct, 80),
                "Constant scan %d/%d" %
                (i + 1, len(functions))
            )

    progress(85, "Deduplicating call patterns")

    groups = collections.defaultdict(list)

    for r in calls:

        f = function(
            int(r["call"], 16)
        )

        if not f:
            continue

        ctx = context(
            int(r["call"], 16), f
        )

        signature = "|".join(
            x["instruction"] for x in ctx
        )

        # Same API + function + context = one pattern.
        groups[
            (r["api"], r["function"], signature)
        ].append(r["call"])

    deduplicated = []

    for key, addresses in groups.items():

        deduplicated.append({
            "api": key[0],
            "function": key[1],
            "instances": len(addresses),
            "addresses": addresses
        })

    progress(93, "Writing reports")

    report = {

        "metadata": {
            "version": "1.0",
            "input": idaapi.get_input_file_path(),
            "imagebase": hx(idaapi.get_imagebase()),
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "elapsed": round(
                time.time() - t0, 2
            )
        },

        "imports": {
            api: [hx(x) for x in addresses]
            for api, addresses in imports.items()
        },

        "callsites": calls,

        "callers": callers,

        "deduplicated": deduplicated,

        "global_constants": dict(
            global_constants
        ),

        "statistics": {
            "apis_found": len(imports),
            "call_xrefs": len(calls),
            "caller_functions": len(callers),
            "deduplicated_patterns": len(deduplicated),
            "functions_scanned": len(functions),
            "unique_constants": len(global_constants)
        }
    }

    with open(output, "wb") as fp:

        data = json.dumps(
            report,
            indent=2,
            sort_keys=True
        )

        fp.write(data.encode("utf-8"))

    tsv = os.path.splitext(output)[0] + ".tsv"

    with open(tsv, "wb") as fp:

        fp.write(
            "API\tCALL\tFUNCTION\tCONFIDENCE\tINSTRUCTION\n"
        )

        for r in calls:

            confidence = (
                "HIGH" if r["is_call"]
                else "MEDIUM"
            )

            line = "%s\t%s\t%s\t%s\t%s\n" % (
                r["api"],
                r["call"],
                r["function"],
                confidence,
                r["disasm"].replace("\t", " ")
            )

            fp.write(line.encode("utf-8"))

    progress(
        100,
        "Complete: %d calls, %d callers" %
        (len(calls), len(callers))
    )

    print("JSON: " + output)
    print("TSV: " + tsv)

    print(
        "100%% = scan completed, "
        "not semantic completeness."
    )

    ida_kernwin.info(
        "NGS2 analysis complete!\n\n" +
        output + "\n" + tsv
    )


try:
    main()

finally:
    ida_kernwin.hide_wait_box()
