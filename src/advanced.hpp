/*
 * advanced.hpp — function-level analyses that leverage rax's emulation results.
 *
 *   - Switch reconstruction : group an indirect jump's resolved targets into a
 *     real IDA switch (custom table, no bytes written).
 *   - Stack purge           : set a callee's argsize from the emulated SP delta.
 *   - No-return             : COMMENT-hint (opt-in FUNC_NORET) when a function
 *                             never returned and halted definitively.
 *   - Argument registers    : COMMENT-hint the read-before-written arg regs.
 *   - Opaque predicate      : COMMENT-hint conditional branches whose one side
 *                             was never reachable across several varied runs.
 *
 * The verifiable changes (switch, purge) are applied directly and guarded; the
 * unattended-inference results (no-return, arg regs, opaque) are comments by
 * default so viy stays "never wrong". Main thread only.
 */
#pragma once

#include <cstdint>
#include <unordered_set>

#include "emu_driver.hpp"     // EmuEvents, EmuOutcome
#include "program_model.hpp"  // ViyArch
#include "viy_config.hpp"

namespace viy {

struct AdvStats
{
  size_t switches = 0;
  size_t purges   = 0;
  size_t norets   = 0;
  size_t argregs  = 0;
  size_t opaque   = 0;
};

// `reached` is the union of executed PCs across the (possibly several) runs used
// for opaque-predicate analysis; empty when opaque analysis is disabled.
// `noret_corroborated` is set by the caller only when SEVERAL varied-input runs
// all failed to return and at least one halted definitively — a single run is
// never trusted for no-return.
void viy_advanced(ViyArch arch, uint64_t func_start, uint64_t func_end,
                  const EmuEvents &ev, const EmuOutcome &outcome,
                  const std::unordered_set<uint64_t> &reached,
                  bool noret_corroborated,
                  const ViyConfig &cfg, AdvStats &stats);

} // namespace viy
