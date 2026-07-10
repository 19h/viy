/*
 * viy_config.hpp — runtime caps for the emulation sweep.
 *
 * Configuration is intentionally minimal and dependency-light: sane defaults,
 * overridable via environment variables with no dialogs or required files.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace viy {

enum class ViyLogLevel : uint8_t
{
  QUIET = 0,
  SUMMARY = 1,
  PROGRESS = 2,
  TRACE = 3,
};

struct ViyConfig
{
  bool     enabled       = true;    // master switch (VIY_ENABLED=0 disables)
  ViyLogLevel log_level  = ViyLogLevel::PROGRESS; // visible bounded lifecycle/progress
  uint64_t progress_interval_ms = 1000; // monotonic progress-log cadence
  uint64_t max_insns     = 200000;  // per-run instruction cap (bounds runaway/loops)
  uint64_t timeout_ms    = 1000;    // per-run wall-clock cap
  uint64_t max_funcs     = 0;       // 0 = every function; else stop after N entries
  int      funcs_per_tick = 2;      // functions emulated per UI timer tick (keeps UI live)
  int      tick_ms       = 15;      // timer cadence
  int      max_epochs    = 3;       // bounded analysis/rediscovery fixed point
  int      explore_runs  = 4;       // deterministic entry-state variants per function
  int      workers       = 0;       // 0 = auto; worker engines, DB apply remains main-thread
  bool     make_code     = true;    // auto_make_code/plan_ea on discovered code targets
  bool     want_drefs    = true;    // record data references (needs a recording backend)
  bool     want_static   = true;    // run the rax static-decode cross-check pass (rax >= 1.2)
  bool     want_native   = true;    // IDA-native analysis providers (works without librax)
  bool     want_deobf    = true;    // additional read-only structural/deobfuscation evidence
  bool     persist_evidence = true; // versioned per-IDB evidence/provenance ledger
  bool     strict_perms  = true;    // honor IDA segment permissions in the guest image
  bool     want_import_summaries = true; // model selected well-known external/library calls
  // Enrichment pass (uses rax's concrete values; all additive, heavily guarded):
  bool     want_ptr_refs = true;    // materialize in-image pointers loaded from memory (offset + dref)
  bool     want_data_types = true;  // type undefined globals by observed access size
  bool     want_comments = true;    // repeatable comments naming what rax resolved
  bool     want_strings  = true;    // detect + create C strings at observed data reads
  bool     want_runtime_strings = true; // reconstruct strings produced by observed writes
  bool     want_unicode_strings = true; // UTF-16/UTF-32 runtime-string candidates
  bool     want_tables   = true;    // cluster pointer slots / indirect-use chains
  bool     want_function_recovery = true; // promote guarded orphan call targets
  bool     want_tail_recovery = false; // append trace-proven function tails (opt-in metadata change)
  bool     want_smc_evidence = true; // record write-then-execute/runtime-image differences
  bool     apply_runtime_bytes = false; // patch runtime bytes into the IDB (explicit opt-in)
  uint64_t max_runtime_bytes = 1ull << 20; // captured final dirty bytes per run
  // Advanced (function-level) analyses:
  bool     want_switch   = false;   // reconstruct switches (opt-in: emulation coverage may be partial)
  bool     want_purge    = true;    // set callee stack purge (x86) from the emulation SP delta
  bool     want_noret    = true;    // COMMENT-hint no-return functions
  bool     set_noret     = false;   // actually set FUNC_NORET (opt-in; re-flows callers)
  bool     want_argregs  = true;    // COMMENT-hint inferred argument registers
  bool     want_opaque   = false;   // multi-run opaque-predicate / dead-branch hints (comment)
  int      opaque_runs   = 3;       // emulation runs used for opaque detection
  bool     want_hexrays_bridge = false; // opt-in decompiler-local warnings/hints; never rewrites IDB
};

// Load config from environment overrides on top of the defaults above.
ViyConfig viy_load_config();

} // namespace viy
