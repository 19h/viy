#!/usr/bin/env python3
"""Strict verifier for viy's structured GUI/headless observability contract."""

import collections
import shlex
import sys


def fail(message):
    raise AssertionError(message)


def integer(record, key):
    try:
        return int(record[key])
    except (KeyError, TypeError, ValueError) as exc:
        raise AssertionError("missing/invalid {} in {}".format(key, record)) from exc


def ratio(record, key):
    try:
        left, right = record[key].split("/", 1)
        return int(left, 10), int(right, 10)
    except (KeyError, ValueError) as exc:
        raise AssertionError("missing/invalid ratio {} in {}".format(key, record)) from exc


def parse(path):
    records = []
    lines = []
    with open(path, "r", encoding="utf-8", errors="strict") as stream:
        for number, raw in enumerate(stream, 1):
            line = raw.rstrip("\n")
            lines.append(line)
            if not line.startswith("[viy] "):
                continue
            structured = line[len("[viy] "):]
            if len(structured.encode("utf-8")) > 2048:
                fail("structured line {} exceeds 2048 bytes".format(number))
            fields = {"_line": number}
            for token in shlex.split(structured):
                if "=" in token:
                    key, value = token.split("=", 1)
                    fields[key] = value
            if "event" not in fields:
                fail("[viy] line {} is not structured".format(number))
            records.append(fields)
    return records, lines


def events(records, name):
    return [record for record in records if record.get("event") == name]


def require_subsequence(values, expected, label):
    cursor = 0
    for value in values:
        if cursor < len(expected) and value == expected[cursor]:
            cursor += 1
    if cursor != len(expected):
        fail("{} missing ordered subsequence {}; got {}".format(
            label, expected, values))


def verify_common(records, level):
    if not records:
        fail("no structured viy records")
    if level == 0:
        fail("quiet verification received structured records")
    if level == 1 and events(records, "progress"):
        fail("summary level emitted progress records")
    if level < 3 and events(records, "worker-result"):
        fail("non-trace level emitted per-function worker records")
    if level >= 2 and not events(records, "progress"):
        fail("progress/trace level emitted no progress records")

    starts = events(records, "start")
    terminals = events(records, "complete")
    if len(starts) != 1 or len(terminals) != 1:
        fail("expected exactly one start and one terminal completion")
    start = starts[0]
    terminal = terminals[0]

    phase_values = [record.get("phase") for record in events(records, "phase")]
    expected = ["waiting-autoanalysis", "snapshotting"]
    if start.get("native") == "on":
        expected.append("native-analysis")
    if start.get("deobfuscation") == "on":
        expected.append("deobfuscation-analysis")
    expected.extend(["sweeping-functions", "applying-evidence", "complete"])
    require_subsequence(phase_values, expected, "phase lifecycle")

    terminal_elapsed = integer(terminal, "elapsed_ms")
    complete_statuses = [record for record in events(records, "status")
                         if record.get("phase") == "complete"]
    if not complete_statuses:
        fail("completion emitted no terminal status projection")
    for record in complete_statuses:
        if integer(record, "elapsed_ms") != terminal_elapsed:
            fail("terminal elapsed time changed after completion")

    for snapshot in events(records, "snapshot"):
        copied, segment_total = ratio(snapshot, "segments")
        if (copied + integer(snapshot, "segment_invalid") +
                integer(snapshot, "segment_read_failures") != segment_total):
            fail("snapshot segment accounting is not exhaustive")
        included, function_total = ratio(snapshot, "functions")
        accounted = (included + integer(snapshot, "functions_null") +
                     integer(snapshot, "functions_library_or_thunk") +
                     integer(snapshot, "functions_excluded_by_limit"))
        if accounted != function_total:
            fail("snapshot function accounting is not exhaustive")

    applies = events(records, "evidence-apply")
    if not applies:
        fail("no evidence application result")
    for applied in applies:
        for key in ("contradiction_relations", "contradiction_digests",
                    "duration_ms", "conflicted", "below_policy"):
            if integer(applied, key) < 0:
                fail("negative evidence application counter")

    if level >= 2:
        progress = events(records, "progress")
        progress_keys = {(r.get("phase"), r.get("stage")) for r in progress}
        for required in (("snapshotting", "segments"),
                         ("snapshotting", "functions"),
                         ("snapshotting", "complete"),
                         ("applying-evidence", "planning"),
                         ("applying-evidence", "mutating"),
                         ("applying-evidence", "complete")):
            if required not in progress_keys:
                fail("missing progress stage {}".format(required))
        if start.get("native") == "on" and \
                ("native-analysis", "complete") not in progress_keys:
            fail("native provider has no completion progress")
        if start.get("deobfuscation") == "on" and \
                ("deobfuscation-analysis", "complete") not in progress_keys:
            fail("deobfuscation provider has no completion progress")

    for provider in events(records, "provider"):
        if provider.get("provider") == "native":
            register_state = provider.get("register_tracker")
            operand_state = provider.get("operand_address_tracker")
            if register_state not in ("unknown", "available", "unavailable"):
                fail("native register-tracker capability is invalid")
            if operand_state not in ("available", "unavailable"):
                fail("native operand-address tracker was not probed")

    capabilities = events(records, "capabilities")
    if not capabilities:
        fail("no capability record")
    snapshot_functions = {
        snapshot.get("epoch"): ratio(snapshot, "functions")[0]
        for snapshot in events(records, "snapshot")
    }
    for capability in capabilities:
        policy = capability.get("workers_policy")
        configured = integer(capability, "workers_configured")
        hardware = integer(capability, "workers_hardware_threads")
        automatic_cap = integer(capability, "workers_auto_cap")
        selected = integer(capability, "workers_selected")
        requested = integer(capability, "workers_requested")
        if min(configured, hardware, selected, requested) < 0:
            fail("negative worker-selection value")
        if automatic_cap != 4:
            fail("unexpected automatic worker cap")
        if selected != requested:
            fail("selected and requested worker counts disagree")
        if policy == "auto":
            if configured != 0 or selected > automatic_cap:
                fail("automatic worker selection violates its cap")
        elif policy == "explicit":
            if configured == 0 or selected > configured:
                fail("explicit worker selection violates configuration")
        else:
            fail("invalid worker selection policy")
        dynamic_capability = capability.get("dynamic")
        if dynamic_capability == "off" and selected != 0:
            fail("dynamic=off selected workers")
        if dynamic_capability != "off":
            functions = snapshot_functions.get(capability.get("epoch"))
            if functions is None or functions <= 0:
                fail("dynamic capability has no nonempty function snapshot")
            if policy == "auto":
                expected_selected = min(
                    max(hardware - 1, 1), automatic_cap, functions)
            else:
                expected_selected = min(configured, functions)
            if selected != expected_selected:
                fail("worker selection does not match declared policy")

    function_passes = integer(terminal, "function_passes")
    jobs = sum(integer(terminal, key) for key in
               ("jobs_completed", "jobs_cancelled", "jobs_unavailable", "jobs_failed"))
    cache_hits = integer(terminal, "cache_hits")
    runs_started, runs_requested = ratio(terminal, "runs_started")
    if runs_started > runs_requested:
        fail("started runs exceed requested runs")

    dynamic = terminal.get("dynamic")
    available, requested = ratio(terminal, "workers_available")
    unavailable = integer(terminal, "workers_unavailable")
    if dynamic == "off":
        if jobs != 0 or cache_hits != 0 or requested != 0:
            fail("dynamic=off has dynamic jobs/cache/workers")
    else:
        if jobs + cache_hits != function_passes:
            fail("dynamic job taxonomy plus cache hits does not equal function passes")
        if dynamic == "available" and not (available == requested and unavailable == 0):
            fail("dynamic=available worker counters disagree")
        if dynamic == "partial" and not (available > 0 and unavailable > 0):
            fail("dynamic=partial worker counters disagree")
        if dynamic == "unavailable" and available != 0:
            fail("dynamic=unavailable reports available workers")

    return start, terminal


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_observability_log.py MODE LOG")
    mode, path = sys.argv[1:]
    records, lines = parse(path)

    if mode == "quiet":
        if records or any("[viy]" in line for line in lines):
            fail("VIY_LOG_LEVEL=0 emitted viy output")
        return

    level = {"summary": 1, "cache": 2, "native": 2, "deobf": 2,
             "hexrays": 2, "manual": 3, "trace": 3}[mode]
    start, terminal = verify_common(records, level)

    if mode == "summary" and events(records, "worker-result"):
        fail("summary mode emitted trace records")
    elif mode == "cache":
        if integer(terminal, "cache_hits") == 0:
            fail("cache mode observed no dynamic cache hit")
        if "waiting-convergence" not in [r.get("phase") for r in events(records, "phase")]:
            fail("cache mode did not expose convergence")
    elif mode in ("native", "deobf"):
        expected = "native" if mode == "native" else "deobfuscation"
        providers = [r.get("provider") for r in events(records, "provider")]
        if providers != [expected] or terminal.get("dynamic") != "off":
            fail("{}-only capability/provider accounting is wrong".format(mode))
        if not any(r.get("scope") == "rax" for r in events(records, "diagnostic")):
            fail("missing companion-engine unavailability diagnostic")
    elif mode == "hexrays":
        if not events(records, "hexrays-publish"):
            fail("Hex-Rays evidence publication was not reported")
    elif mode == "manual":
        marker = [line for line in lines if "VIY_OBSERVABILITY_SMOKE" in line]
        if not marker or "early=1 first=1 second=1" not in marker[-1]:
            fail("manual plugin entry was not invoked twice")
        waiting_statuses = [r for r in events(records, "status")
                            if r.get("phase") == "waiting-autoanalysis"]
        if not waiting_statuses:
            fail("early manual invocation bypassed/no longer reports autoanalysis wait")
        auto_finished = [i + 1 for i, line in enumerate(lines)
                         if "The initial autoanalysis has been finished." in line]
        if not auto_finished or integer(start, "_line") <= auto_finished[-1]:
            fail("analysis started before IDA's final autoanalysis boundary")
        terminal_elapsed = integer(terminal, "elapsed_ms")
        statuses = [r for r in events(records, "status")
                    if r.get("phase") == "complete"]
        if len(statuses) < 3 or any(integer(r, "elapsed_ms") != terminal_elapsed
                                    for r in statuses):
            fail("manual terminal snapshots are absent or not frozen")
    elif mode == "trace":
        results = events(records, "worker-result")
        if not results:
            fail("trace mode emitted no worker results")
        observed = collections.Counter(r.get("status") for r in results)
        expected = {
            "completed": integer(terminal, "jobs_completed"),
            "cancelled": integer(terminal, "jobs_cancelled"),
            "unavailable": integer(terminal, "jobs_unavailable"),
            "failed": integer(terminal, "jobs_failed"),
        }
        if any(observed[name] != count for name, count in expected.items()):
            fail("trace worker-result taxonomy disagrees with terminal counters")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # make CTest/shell failure self-describing
        print("observability verification failed: {}".format(exc), file=sys.stderr)
        raise
