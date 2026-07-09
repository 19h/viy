/*
 * ref_discovery.hpp — turn emulation events into the refs IDA's analysis missed.
 *
 * Runs on the MAIN THREAD (it reads and writes the database). For each observed
 * control-transfer edge and data access it: (1) classifies the kind of ref,
 * (2) checks that the target is inside the image, (3) diffs against the existing
 * xrefs, and (4) adds ONLY what is missing (marked XREF_USER so it survives
 * reanalysis). Discovered code targets are queued for analysis.
 */
#pragma once

#include <cstddef>

#include "emu_driver.hpp" // EmuEvents
#include "viy_config.hpp"

namespace viy {

struct RefStats
{
  size_t crefs = 0;      // missing code refs added (indirect calls/jumps resolved)
  size_t drefs = 0;      // missing data refs added (computed accesses)
  size_t code_made = 0;  // discovered code targets queued for analysis
};

// Apply the missing refs implied by `ev`. Main thread only. Returns counts.
RefStats viy_apply_missing(const EmuEvents &ev, const ViyConfig &cfg);

// Add a code xref from->to if it is genuinely missing, applying every safety
// guard (target in an executable segment and at an instruction head; source is
// a real instruction; not already present). Marks it XREF_USER and, when
// cfg.make_code is set, turns an unexplored target into code. Returns true if a
// ref was added. Shared by the emulation and static-decode passes. Addresses are
// linear (ea_t under the hood). Main thread only.
bool viy_try_add_cref(uint64_t from, uint64_t to, bool is_call,
                      const ViyConfig &cfg, RefStats &stats);

} // namespace viy
