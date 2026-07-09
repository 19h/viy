/*
 * viy_config.hpp — runtime caps for the emulation sweep.
 *
 * Configuration is intentionally minimal and dependency-light: sane defaults,
 * overridable via environment variables (so it stays invisible — no dialogs, no
 * required files). See viy.cfg for the documented knobs.
 */
#pragma once

#include <cstddef>
#include <cstdint>

namespace viy {

struct ViyConfig
{
  bool     enabled       = true;    // master switch (VIY_ENABLED=0 disables)
  uint64_t max_insns     = 200000;  // per-run instruction cap (bounds runaway/loops)
  uint64_t timeout_ms    = 1000;    // per-run wall-clock cap
  uint64_t max_funcs     = 0;       // 0 = every function; else stop after N entries
  int      funcs_per_tick = 2;      // functions emulated per UI timer tick (keeps UI live)
  int      tick_ms       = 15;      // timer cadence
  bool     make_code     = true;    // auto_make_code/plan_ea on discovered code targets
  bool     want_drefs    = true;    // record data references (needs a recording backend)
  bool     want_static   = true;    // run the rax static-decode cross-check pass (rax >= 1.2)
  // Enrichment pass (uses rax's concrete values; all additive, heavily guarded):
  bool     want_ptr_refs = true;    // materialize in-image pointers loaded from memory (offset + dref)
  bool     want_data_types = true;  // type undefined globals by observed access size
  bool     want_comments = true;    // repeatable comments naming what rax resolved
  bool     want_strings  = true;    // detect + create C strings at observed data reads
  // Advanced (function-level) analyses:
  bool     want_switch   = false;   // reconstruct switches (opt-in: emulation coverage may be partial)
  bool     want_purge    = true;    // set callee stack purge (x86) from the emulation SP delta
  bool     want_noret    = true;    // COMMENT-hint no-return functions
  bool     set_noret     = false;   // actually set FUNC_NORET (opt-in; re-flows callers)
  bool     want_argregs  = true;    // COMMENT-hint inferred argument registers
  bool     want_opaque   = false;   // multi-run opaque-predicate / dead-branch hints (comment)
  int      opaque_runs   = 3;       // emulation runs used for opaque detection
};

// Load config from environment overrides on top of the defaults above.
ViyConfig viy_load_config();

} // namespace viy
