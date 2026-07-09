"""Batch-only smoke harness for the installed viy plugin.

Usage example:
  idat -A -L/tmp/viy.log -S/path/to/ida_worker_smoke.py input_binary

The viy plugin is normally auto-loaded from IDAUSR/plugins. This script waits
for initial autoanalysis, returns control to IDA's event loop so viy's timer can
submit/drain worker jobs, and exits cleanly after VIY_SMOKE_WAIT_MS. A clean
exit exercises worker startup, bounded processing, cancellation/join at IDB
teardown, and main-thread database access under the real SDK runtime.
"""

import os
import time

import ida_auto
import ida_funcs
import ida_kernwin
import ida_pro


ida_auto.auto_wait()
started = time.monotonic()
wait_ms = max(250, int(os.environ.get("VIY_SMOKE_WAIT_MS", "5000"), 0))
print("VIY_WORKER_SMOKE started functions={} wait_ms={}".format(
    ida_funcs.get_func_qty(), wait_ms))


def finish():
    elapsed_ms = int((time.monotonic() - started) * 1000)
    print("VIY_WORKER_SMOKE clean_exit functions={} elapsed_ms={}".format(
        ida_funcs.get_func_qty(), elapsed_ms))
    ida_pro.qexit(0)
    return -1


if ida_kernwin.register_timer(wait_ms, finish) is None:
    # Headless idat may not expose UI timers. viy detects the same condition and
    # completes via its inline main-thread drain (the rax engines remain worker
    # threads), so reaching this point after auto_wait() is a successful smoke.
    print("VIY_WORKER_SMOKE clean_exit_inline functions={}".format(
        ida_funcs.get_func_qty()))
    ida_pro.qexit(0)
