/*
 * static_decoder.hpp — leverage rax's static decoder to enhance analysis.
 *
 * A complement to the emulation pass. Where the emulator resolves INDIRECT
 * control flow (jump tables, vtable/computed calls), rax's static decoder
 * resolves DIRECT control flow with certainty and without executing anything.
 * This pass cross-checks the decode: for a control-transfer instruction that
 * IDA left without a resolved code target, it asks rax whether the encoding
 * carries a direct target, and adds the cref if so.
 *
 * It only ever adds a reference through viy_try_add_cref, so every safety guard
 * (executable target, instruction head, add-only-if-missing) applies. Runs on
 * the main thread. A no-op when rax's decoder is unavailable (older librax) or
 * the architecture cannot be decoded unambiguously here.
 */
#pragma once

#include <cstdint>

#include "rax_loader.hpp"
#include "program_model.hpp"
#include "viy_config.hpp"
#include "ref_discovery.hpp" // RefStats, viy_try_add_cref

namespace viy {

// Statically decode one function's instructions with rax and recover missing
// direct crefs. Accumulates into `stats`. Main thread only.
void viy_static_decode_func(const RaxApi *api, ViyArch arch, bool big_endian,
                            uint64_t func_start, uint64_t func_end,
                            const ViyConfig &cfg, RefStats &stats);

} // namespace viy
