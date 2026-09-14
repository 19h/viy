"""Run with IDAT -A -S on a disposable IDB; never use a production database."""
import json
import os
import time
import traceback

import ida_auto
import ida_bytes
import ida_idaapi
import ida_pro
import ida_segment
import ida_ua
import ida_xref


def sorted_exists(source, target, flags):
    cursor = ida_xref.xrefblk_t()
    found = (cursor.first_from(source, flags) if target == 0
             else cursor.next_from(source, target - 1, flags))
    return found and cursor.to == target


def code_exists(source, target):
    cursor = ida_xref.xrefblk_t()
    if cursor.first_from(source, ida_xref.XREF_CODE) and cursor.to == target:
        return True
    return sorted_exists(source, target, ida_xref.XREF_CODE | ida_xref.XREF_NOFLOW)


def linear_exists(source, target):
    cursor = ida_xref.xrefblk_t()
    found = cursor.first_from(source, ida_xref.XREF_DATA)
    while found:
        if cursor.to == target:
            return True
        found = cursor.next_from()
    return False


def main():
    ida_auto.auto_wait()
    assert ida_segment.getseg(0) is None, "fixture requires an unused low address range"
    assert ida_segment.add_segm(0, 0, 0x20000, "VIY_XREF_TEST", "CODE")
    ida_bytes.patch_bytes(0x100, b"\x90\x90\xc3")
    assert ida_ua.create_insn(0x100) > 0
    assert ida_ua.create_insn(0x101) > 0
    ida_auto.auto_wait()
    source = 0x100
    ida_bytes.del_items(0x200, ida_bytes.DELIT_SIMPLE, 16)
    ida_bytes.patch_bytes(0x200, b"\xb8\x01\x00\x00\x00")
    width = ida_ua.create_insn(0x200)
    assert width > 1
    for address in range(0x200, 0x200 + width):
        # Production dref gate must reject both the instruction head and tails.
        assert ida_bytes.is_code(ida_bytes.get_flags(ida_bytes.get_item_head(address)))
        if address != 0x200:
            assert ida_bytes.is_tail(ida_bytes.get_flags(address))
            assert not ida_bytes.is_code(ida_bytes.get_flags(address))
    ida_bytes.del_items(0x400, ida_bytes.DELIT_SIMPLE, 4)
    assert ida_bytes.create_data(0x400, ida_bytes.FF_DWORD, 4, ida_idaapi.BADADDR)
    for address in range(0x400, 0x404):
        assert not ida_bytes.is_code(ida_bytes.get_flags(ida_bytes.get_item_head(address)))
    targets = set(range(0x1000, 0x3000, 8)) | {0}
    for target in sorted(targets):
        assert ida_xref.add_dref(source, target, ida_xref.dr_R | ida_xref.XREF_USER)
    for target in range(0x3002):
        assert sorted_exists(source, target, ida_xref.XREF_DATA) == (target in targets)
    for target in (0, 0x80, 0x4000):
        assert ida_xref.add_cref(source, target, ida_xref.fl_JN | ida_xref.XREF_USER)
    assert ida_xref.add_cref(source, source + 1, ida_xref.fl_F)
    for target in (0, 1, 0x7F, 0x80, source + 1, 0x3FFF, 0x4000, 0x4001):
        assert code_exists(source, target) == (target in {0, 0x80, source + 1, 0x4000})
    ida_xref.del_dref(source, 0x1000)
    assert not sorted_exists(source, 0x1000, ida_xref.XREF_DATA)
    assert ida_xref.add_dref(source, 0x1001, ida_xref.dr_W | ida_xref.XREF_USER)
    assert sorted_exists(source, 0x1001, ida_xref.XREF_DATA)

    result = {"status": "passed", "references": len(targets)}
    # Same absent target above all existing refs: exposes full-list rescanning.
    for name, lookup in (("linear", linear_exists),
                         ("seek", lambda src, dst: sorted_exists(src, dst, ida_xref.XREF_DATA))):
        started = time.perf_counter()
        for _ in range(1000):
            assert not lookup(source, 0x4001)
        result[name + "_seconds"] = time.perf_counter() - started
    return result


try:
    output = main()
    status = 0
except Exception:
    output = {"status": "failed", "traceback": traceback.format_exc()}
    status = 1
with open(os.environ["VIY_XREF_TEST_RESULT"], "w", encoding="utf-8") as stream:
    json.dump(output, stream, indent=2)
ida_pro.qexit(status)
