"""Exercise viy's public manual-status entry after terminal completion."""

import os
import time

import ida_auto
import ida_loader
import ida_pro


delay_ms = max(100, int(os.environ.get("VIY_OBSERVABILITY_DELAY_MS", "150"), 0))

early = ida_loader.load_and_run_plugin("viy", 0)
ida_auto.auto_wait()
first = ida_loader.load_and_run_plugin("viy", 0)
time.sleep(delay_ms / 1000.0)
second = ida_loader.load_and_run_plugin("viy", 0)
print("VIY_OBSERVABILITY_SMOKE early={} first={} second={} delay_ms={}".format(
    int(bool(early)), int(bool(first)), int(bool(second)), delay_ms))
if not early or not first or not second:
    raise AssertionError("viy public run entry was not invokable")
ida_pro.qexit(0)
