"""Run with the pointer_observations fixture in a fresh disposable IDB.

VIY_POINTER_COMMENT_CASE: fresh, legacy, correlated, edited, or local-conflict.
"""

import os
import traceback

import ida_auto
import ida_bytes
import ida_idaapi
import ida_loader
import ida_name
import ida_pro


def run():
    # Seed before auto_wait: an installed viy can start from auto_empty_finally.
    base = ida_name.get_name_ea(ida_idaapi.BADADDR, "_observed_slots")
    if base == ida_idaapi.BADADDR:
        base = ida_name.get_name_ea(ida_idaapi.BADADDR, "observed_slots")
    assert base != ida_idaapi.BADADDR, "missing fixture pointer slots"
    case = os.environ.get("VIY_POINTER_COMMENT_CASE", "fresh")
    legacy = "viy: corroborated runtime pointer table (2 contiguous slot(s))"
    original = ""
    if case in ("legacy", "local-conflict"):
        original = legacy
    elif case == "correlated":
        original = legacy + "; indirect use observed"
    elif case == "edited":
        original = legacy + "; analyst note: inspect consumers"
    else:
        assert case == "fresh", case
    if original:
        assert ida_bytes.set_cmt(base, original, True)
    if case == "local-conflict":
        assert ida_bytes.set_cmt(base, "analyst local note", False)
    ida_auto.auto_wait()
    assert ida_loader.load_and_run_plugin("viy", 0)
    ida_auto.auto_wait()
    local = ida_bytes.get_cmt(base, False) or ""
    repeatable = ida_bytes.get_cmt(base, True) or ""
    if case == "local-conflict":
        assert local == "analyst local note", local
        assert repeatable == original, repeatable
    else:
        assert local.startswith("viy: 2 adjacent pointer slots; values repeated in at least "), local
        assert "table" not in local and "indirect" not in local, local
        assert repeatable == (original if case == "edited" else ""), repeatable
    print("VIY_POINTER_COMMENTS case={} passed".format(case))


try:
    run()
except Exception:
    traceback.print_exc()
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
