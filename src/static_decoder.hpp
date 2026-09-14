/* Recover unresolved direct control references from worker decoder results.
 * viy_try_add_cref retains the target/head/existence checks. IDB mutations are
 * main-thread-only; stateless RAX analysis has already completed on a worker. */
#pragma once

#include <cstdint>

#include "decoder_audit.hpp"
#include "program_model.hpp"
#include "viy_config.hpp"
#include "ref_discovery.hpp" // RefStats, viy_try_add_cref

namespace viy {

// Recover missing direct crefs from a completed worker audit. Main thread only;
// no RAX calls or redundant full-function decoding occur during application.
void viy_apply_static_decode(
    const std::vector<DecoderAuditInstruction> &instructions,
    const ViyConfig &cfg, RefStats &stats);

} // namespace viy
