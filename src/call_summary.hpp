/* Main-thread discovery of well-known callable environment summaries. */
#pragma once

#include <vector>

#include "emu_driver.hpp"

namespace viy {

// Uses IDA names only; returned entries are POD and safe to hand to workers.
std::vector<EmuCallSummary> viy_collect_call_summaries();

} // namespace viy
