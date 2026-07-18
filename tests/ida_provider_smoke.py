"""Assert that a selected rax-disabled provider persisted real-IDB facts."""

import os
import traceback

import ida_auto
import ida_loader
import ida_netnode
import ida_pro


MARKER = "$ viy:evidence:v1"
SLOTS = {1: "$ viy:evidence:v1:a", 2: "$ viy:evidence:v1:b"}
TAG = ord("V")


def run():
    ida_auto.auto_wait()
    ida_loader.load_and_run_plugin("viy", 0)
    ida_auto.auto_wait()
    expected = os.environ["VIY_EXPECT_PRODUCER"].encode("ascii")
    if not ida_netnode.netnode.exist(MARKER):
        raise AssertionError("provider did not create the evidence marker")
    marker = ida_netnode.netnode(MARKER)
    active = int(marker.altval(0))
    if active not in SLOTS or not ida_netnode.netnode.exist(SLOTS[active]):
        raise AssertionError("provider did not commit an evidence slot")
    blob = ida_netnode.netnode(SLOTS[active]).getblob(0, TAG)
    if not blob or expected not in blob:
        raise AssertionError("missing persisted producer {!r}".format(expected))
    print("VIY_PROVIDER_SMOKE producer={} bytes={}".format(
        expected.decode("ascii"), len(blob)))


try:
    run()
except Exception:
    traceback.print_exc()
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
