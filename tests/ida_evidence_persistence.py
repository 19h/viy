"""Real-IDB crash-recovery probe for viy's two-slot evidence ledger.

The shell harness invokes this script in several fresh IDA processes.  Modes
are selected through VIY_EVIDENCE_MODE; failures always exit IDA non-zero.
"""

import hashlib
import json
import os
import struct
import traceback

import ida_auto
import ida_loader
import ida_netnode
import ida_pro


NODE_NAME = "$ viy:evidence:v1"
SLOT_NAMES = {
    1: "$ viy:evidence:v1:a",
    2: "$ viy:evidence:v1:b",
}
BLOB_TAG = ord("V")
SLOT_A = 1
SLOT_B = 2
MAGIC = b"VIYEVDB\x00"


def decode_envelope(blob):
    if blob is None or len(blob) < 56:
        raise AssertionError("missing or undersized evidence envelope")
    if blob[:8] != MAGIC:
        raise AssertionError("bad evidence magic")
    if hashlib.sha256(blob[:-32]).digest() != blob[-32:]:
        raise AssertionError("bad evidence SHA-256")
    major, minor, flags = struct.unpack_from(">HHI", blob, 8)
    count = struct.unpack_from(">Q", blob, 16)[0]
    if (major, minor, flags) != (1, 0, 1):
        raise AssertionError(
            "unexpected evidence schema {}.{} flags {}".format(major, minor, flags))
    return {"size": len(blob), "count": count}


def node():
    if not ida_netnode.netnode.exist(NODE_NAME):
        raise AssertionError("viy evidence netnode does not exist")
    return ida_netnode.netnode(NODE_NAME)


def slot_blob(nn, slot):
    del nn  # the marker node deliberately stores no large blobs
    name = SLOT_NAMES[slot]
    if not ida_netnode.netnode.exist(name):
        return None
    return ida_netnode.netnode(name).getblob(0, BLOB_TAG)


def set_slot_blob(slot, blob):
    name = SLOT_NAMES[slot]
    if ida_netnode.netnode.exist(name):
        nn = ida_netnode.netnode(name)
    else:
        nn = ida_netnode.netnode()
        if not nn.create(name):
            raise AssertionError("could not create evidence slot node")
    if not nn.setblob(blob, 0, BLOB_TAG):
        raise AssertionError("could not write evidence slot node")


def save_state(value):
    path = os.environ.get("VIY_EVIDENCE_STATE")
    if not path:
        raise AssertionError("VIY_EVIDENCE_STATE is required")
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)


def load_state():
    with open(os.environ["VIY_EVIDENCE_STATE"], "r", encoding="utf-8") as stream:
        return json.load(stream)


def run_mode():
    ida_auto.auto_wait()
    # A fully analyzed reopened IDB may not emit another auto_empty_finally
    # notification after plugmod construction. Kick the hidden plugin through
    # its public run entry; the per-IDB `started` guard makes this idempotent.
    ida_loader.load_and_run_plugin("viy", 0)
    ida_auto.auto_wait()
    mode = os.environ.get("VIY_EVIDENCE_MODE", "verify")
    nn = node()
    active = int(nn.altval(0))

    if mode == "verify":
        if active not in (SLOT_A, SLOT_B):
            raise AssertionError("no committed evidence slot: {}".format(active))
        info = decode_envelope(slot_blob(nn, active))
        if info["count"] == 0:
            raise AssertionError("persisted evidence store is empty")
        print("VIY_EVIDENCE verify active={} count={} size={}".format(
            active, info["count"], info["size"]))

    elif mode == "corrupt_active":
        if active not in (SLOT_A, SLOT_B):
            raise AssertionError("cannot corrupt invalid active marker")
        fallback = SLOT_B if active == SLOT_A else SLOT_A
        active_blob = slot_blob(nn, active)
        active_info = decode_envelope(active_blob)
        try:
            fallback_info = decode_envelope(slot_blob(nn, fallback))
        except AssertionError:
            # A reopened, already-converged IDB need not schedule a new viy
            # sweep. Seed the retained fallback with the last committed bytes;
            # the recovery behavior under test begins after this setup step.
            set_slot_blob(fallback, active_blob)
            fallback_info = active_info
        corrupt = bytearray(active_blob)
        corrupt[-1] ^= 0x80
        set_slot_blob(active, bytes(corrupt))
        save_state({"corrupted": active, "fallback": fallback,
                    "fallback_count": fallback_info["count"]})
        print("VIY_EVIDENCE corrupted active={} fallback={}".format(active, fallback))

    elif mode == "expect_fallback":
        expected = load_state()
        if active != int(expected["fallback"]):
            raise AssertionError("adapter did not repair marker to fallback: {}".format(active))
        info = decode_envelope(slot_blob(nn, active))
        if info["count"] < int(expected["fallback_count"]):
            raise AssertionError("fallback recovery lost observations")
        print("VIY_EVIDENCE fallback_recovered active={} count={}".format(
            active, info["count"]))

    elif mode == "invalidate_marker":
        active_blob = slot_blob(nn, active)
        decode_envelope(active_blob)
        infos = {}
        for slot in (SLOT_A, SLOT_B):
            try:
                infos[slot] = decode_envelope(slot_blob(nn, slot))
            except AssertionError:
                set_slot_blob(slot, active_blob)
                infos[slot] = decode_envelope(active_blob)
        first = infos[SLOT_A]
        second = infos[SLOT_B]
        save_state({"minimum_merged_count": max(first["count"], second["count"])})
        if not nn.altset(0, 99):
            raise AssertionError("could not invalidate commit marker")
        print("VIY_EVIDENCE invalidated_marker counts={},{}".format(
            first["count"], second["count"]))

    elif mode == "expect_marker_merge":
        expected = load_state()
        if active != SLOT_A:
            raise AssertionError("invalid-marker merge did not commit slot A")
        info = decode_envelope(slot_blob(nn, active))
        if info["count"] < int(expected["minimum_merged_count"]):
            raise AssertionError("slot merge lost observations")
        print("VIY_EVIDENCE marker_merge_recovered count={}".format(info["count"]))

    elif mode == "setup_legacy_layout":
        blob = slot_blob(nn, active)
        info = decode_envelope(blob)
        if not nn.setblob(blob, active, BLOB_TAG):
            raise AssertionError("could not stage legacy same-node envelope")
        for name in SLOT_NAMES.values():
            if ida_netnode.netnode.exist(name):
                ida_netnode.netnode(name).kill()
        save_state({"legacy_slot": active, "legacy_count": info["count"]})
        print("VIY_EVIDENCE legacy_layout_staged slot={} count={}".format(
            active, info["count"]))

    elif mode == "expect_legacy_migration":
        expected = load_state()
        slot = int(expected["legacy_slot"])
        if active != slot:
            raise AssertionError("legacy migration changed the committed slot")
        info = decode_envelope(slot_blob(nn, slot))
        if info["count"] < int(expected["legacy_count"]):
            raise AssertionError("legacy migration lost observations")
        print("VIY_EVIDENCE legacy_layout_migrated slot={} count={}".format(
            slot, info["count"]))

    else:
        raise AssertionError("unknown VIY_EVIDENCE_MODE={!r}".format(mode))

    if not ida_loader.save_database():
        raise AssertionError("could not save integration database")


try:
    run_mode()
except Exception:
    traceback.print_exc()
    ida_pro.qexit(1)
else:
    ida_pro.qexit(0)
