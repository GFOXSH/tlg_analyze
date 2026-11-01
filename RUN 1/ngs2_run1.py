
# -*- coding: utf-8 -*-
# NGS2 RUN 1 COMPACT
# IDA 7.x / IDAPython / Python 2.7

from __future__ import print_function

import os
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

TARGETS = [
    0x1AC510,
    0x1A9690,
    0x1ADC10,
    0x1AEFD0,
    0x1AB580,
    0x1B2010,
]

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
    "sceNgs2VoiceGetState",
]

VALUES = {
    0x00000001: "MATRIX_LEVELS",
    0x00000002: "PORT_VOLUME",
    0x00000003: "PORT_MATRIX",
    0x00000005: "PATCH",
    0x00000006: "KICK_EVENT",
    0x10000000: "SAMPLER_SETUP",
    0x10000001: "ADD_WAVEFORM_BLOCKS",
    0x10000005: "PITCH",
    0x10000006: "ENVELOPE",
    0x10000008: "SAMPLER_USER_FX",
    0x10000009: "PEAK_METER",
    0x1000000A: "SAMPLER_FILTER",
    0x20000000: "SUBMIXER_SETUP",
    0x20000002: "COMPRESSOR",
    0x20000004: "SUBMIXER_USER_FX",
    0x20000005: "UNKNOWN_20000005",
    0x20000006: "SUBMIXER_FILTER",
    0x20010000: "REVERB_SETUP",
    0x20010001: "I3DL2",
    0x30000000: "MASTERING_SETUP",
    0x30000002: "LFE_FILTER",
    0x30000003: "LIMITER",
    0x30000004: "GAIN",
    0x30000005: "OUTPUT",
    0x40020000: "CUSTOM_SETUP",
    0x40001C00: "CHORUS",
    0x40001D00: "DELAY",
    0x40002000: "UNKNOWN_40002000",
    0x1000: "RACK_SAMPLER",
    0x2000: "RACK_SUBMIXER",
    0x2001: "RACK_REVERB",
    0x3000: "RACK_MASTERING",
    0x4002: "RACK_CUSTOM",
    0xBB80: "48000_HZ",
    0x100: "256_SAMPLES",
    0x200: "512_SAMPLES",
}

VALUES64 = {
    0x0000000120000005: "PARAM_20000005_64",
    0x0000000140002000: "PARAM_40002000_64",
    0x0000000140001C00: "PARAM_40001C00_64",
    0x0000000140001D00: "PARAM_40001D00_64",
}

def hx(v):
    return "0x%X" % (long(v) & 0xFFFFFFFFFFFFFFFF)

def fname(ea):
    return ida_name.get_name(ea) or idc.get_func_name(ea) or ""

def getfunc(ea):
    return ida_funcs.get_func(ea)

def bounds(f):
    try:
        return f.start_ea, f.end_ea
    except:
        return f.startEA, f.endEA

def disasm(ea):
    try:
        return idc.generate_disasm_line(ea, 0) or ""
    except:
        return idc.GetDisasm(ea) or ""

def mnem(ea):
    try:
        return idc.print_insn_mnem(ea).lower()
    except:
        return ""

def label(v):
    v = long(v) & 0xFFFFFFFFFFFFFFFF
    if v in VALUES64:
        return VALUES64[v]
    if v in VALUES:
        return VALUES[v]
    low = v & 0xFFFFFFFF
    return VALUES.get(low)

def save_json(path, obj):
    with codecs.open(path, "w", "utf-8") as fp:
        fp.write(json.dumps(
            obj, indent=2, sort_keys=True,
            ensure_ascii=True
        ))

def get_operands(ea):
    result = []
    for op in range(8):
        try:
            typ = idc.get_operand_type(ea, op)
            txt = idc.print_operand(ea, op)
            if not txt:
                continue

            item = {"n": op, "type": typ, "text": txt}

            if typ in (
                idc.o_imm, idc.o_mem,
                idc.o_near, idc.o_far
            ):
                v = long(idc.get_operand_value(ea, op))
                item["value"] = hx(v)
                item["label"] = label(v)

            result.append(item)
        except:
            pass
    return result

def instruction_row(ea):
    return {
        "ea": hx(ea),
        "mnemonic": mnem(ea),
        "disasm": disasm(ea),
        "operands": get_operands(ea),
    }

def xrefs_to(ea):
    result = []
    try:
        for x in idautils.XrefsTo(ea, 0):
            src = x.frm
            f = getfunc(src)
            fs = bounds(f)[0] if f else None
            result.append({
                "from": hx(src),
                "function": fname(fs) if fs is not None else "",
                "function_start": hx(fs) if fs is not None else None,
                "instruction": disasm(src),
                "mnemonic": mnem(src),
            })
    except:
        pass
    return result

def target_analysis(ea):
    f = getfunc(ea)
    if not f:
        return {
            "requested": hx(ea),
            "found": False
        }

    start, end = bounds(f)
    instructions = [
        instruction_row(x)
        for x in idautils.Heads(start, end)
    ]

    return {
        "requested": hx(ea),
        "found": True,
        "name": fname(start),
        "start": hx(start),
        "end": hx(end),
        "size": end - start,
        "xrefs_to_entry": xrefs_to(start),
        "instructions": instructions,
    }

def find_imports():
    result = collections.defaultdict(set)

    for ea, n in idautils.Names():
        for api in APIS:
            if api.lower() in n.lower():
                result[api].add(ea)

    for ea in idautils.Functions():
        n = fname(ea)
        for api in APIS:
            if api.lower() in n.lower():
                result[api].add(ea)

    return result

def api_analysis(imports):
    result = []

    for api, addresses in imports.items():
        for target in addresses:
            for x in idautils.XrefsTo(target, 0):
                ea = x.frm
                f = getfunc(ea)
                fs = bounds(f)[0] if f else None

                result.append({
                    "api": api,
                    "target": hx(target),
                    "callsite": hx(ea),
                    "function": fname(fs) if fs is not None else "",
                    "function_start": hx(fs) if fs is not None else None,
                    "instruction": disasm(ea),
                    "mnemonic": mnem(ea),
                })

    return result

def global_constant_scan():
    result = collections.defaultdict(list)
    funcs = list(idautils.Functions())

    for i, fea in enumerate(funcs):
        f = getfunc(fea)
        if not f:
            continue

        start, end = bounds(f)

        for ea in idautils.Heads(start, end):
            for op in range(8):
                try:
                    if idc.get_operand_type(ea, op) != idc.o_imm:
                        continue

                    v = long(
                        idc.get_operand_value(ea, op)
                    ) & 0xFFFFFFFFFFFFFFFF

                    tag = label(v)
                    if not tag:
                        continue

                    key = hx(v)

                    # Только адреса и метаданные, без копии листинга.
                    result[key].append({
                        "ea": hx(ea),
                        "function": fname(fea),
                        "function_start": hx(fea),
                        "operand": op,
                    })
                except:
                    pass

        if i % 250 == 0:
            pct = 55 + int(
                30.0 * (i + 1) / max(1, len(funcs))
            )
            msg = "[NGS2 RUN1 %d%%] Constants %d/%d" % (
                pct, i + 1, len(funcs)
            )
            print(msg)
            try:
                ida_kernwin.replace_wait_box(msg)
            except:
                pass

    return dict(result), len(funcs)

def write_asm(path, targets):
    with codecs.open(path, "w", "utf-8") as fp:
        fp.write("NGS2 RUN1 TARGET DISASSEMBLY\n")

        for ea in targets:
            f = getfunc(ea)
            fp.write("\n========================================\n")

            if not f:
                fp.write("NOT FOUND: %s\n" % hx(ea))
                continue

            start, end = bounds(f)
            fp.write(
                "%s %s - %s\n" %
                (fname(start), hx(start), hx(end))
            )

            for addr in idautils.Heads(start, end):
                fp.write(
                    "%s  %s\n" %
                    (hx(addr), disasm(addr))
                )

def main():
    base = ida_kernwin.ask_file(
        True, "*.json",
        "Save NGS2 RUN1 compact report"
    )
    if not base:
        return

    if not base.lower().endswith(".json"):
        base += ".json"

    root = os.path.splitext(base)[0]
    targets_path = root + "_targets.json"
    api_path = root + "_api.json"
    constants_path = root + "_constants.json"
    asm_path = root + "_targets.asm.txt"
    tsv_path = root + "_constants.tsv"

    ida_kernwin.show_wait_box("NGS2 RUN1 compact analysis")

    try:
        print("[NGS2 RUN1 5%%] Target functions")

        targets = {}
        for ea in TARGETS:
            targets[hx(ea)] = target_analysis(ea)

        save_json(targets_path, {
            "metadata": {
                "version": "2.1-compact",
                "input": idaapi.get_input_file_path(),
                "imagebase": hx(idaapi.get_imagebase()),
                "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "targets": targets,
        })

        print("[NGS2 RUN1 25%%] API references")

        imports = find_imports()
        refs = api_analysis(imports)

        save_json(api_path, {
            "imports": {
                api: [hx(x) for x in addresses]
                for api, addresses in imports.items()
            },
            "references": refs,
        })

        print("[NGS2 RUN1 50%%] Global constants")

        constants, function_count = global_constant_scan()

        save_json(constants_path, {
            "functions_scanned": function_count,
            "constants": constants,
        })

        print("[NGS2 RUN1 90%%] Writing listings")

        write_asm(asm_path, TARGETS)

        with codecs.open(tsv_path, "w", "utf-8") as fp:
            fp.write("VALUE\tLABEL\tEA\tFUNCTION\tFUNCTION_START\tOPERAND\n")

            for value, rows in sorted(constants.items()):
                # TSV labels are resolved from the constant value.
                v = long(value, 16)
                tag = label(v) or ""

                for row in rows:
                    fp.write(
                        "%s\t%s\t%s\t%s\t%s\t%d\n" %
                        (
                            value, tag, row["ea"],
                            row["function"],
                            row["function_start"],
                            row["operand"]
                        )
                    )

        print("[NGS2 RUN1 100%%] Complete")

        paths = [
            targets_path, api_path,
            constants_path, asm_path, tsv_path
        ]

        message = "NGS2 RUN1 complete:\n\n"
        for path in paths:
            try:
                size = os.path.getsize(path)
                message += "%s  (%0.2f MB)\n" % (
                    os.path.basename(path),
                    size / 1048576.0
                )
            except:
                message += path + "\n"

        print(message)
        ida_kernwin.info(message)

    finally:
        ida_kernwin.hide_wait_box()

try:
    main()
except Exception as e:
    print("[NGS2 RUN1 ERROR] %s" % str(e))
    raise
