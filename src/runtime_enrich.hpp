/*
 * runtime_enrich.hpp -- guarded annotations derived from final emulated memory.
 *
 * This pass consumes the exact final-write buffers and per-run provenance from
 * EmuEvents. It is deliberately separate from the emulator: all IDA reads and
 * mutations happen in runtime_enrich.cpp on the main thread.
 */
#pragma once

#include <cstddef>

#include "emu_driver.hpp"
#include "program_model.hpp"
#include "viy_config.hpp"

namespace viy {

struct RuntimeEnrichStats
{
  // Input/corroboration accounting.
  size_t final_write_observations = 0;
  size_t corroborated_write_groups = 0;
  size_t uncorroborated_write_groups = 0;
  size_t conflicting_write_ranges = 0;

  // Runtime strings.
  size_t string_observations = 0;
  size_t string_candidates = 0;
  size_t strings_corroborated = 0;
  size_t ascii_strings = 0;
  size_t utf8_strings = 0;
  size_t utf16_strings = 0;
  size_t utf32_strings = 0;
  size_t strings_created = 0;
  size_t stack_string_comments = 0;
  size_t runtime_only_string_comments = 0;
  size_t strings_skipped_defined = 0;
  size_t strings_skipped_conflict = 0;

  // Runtime bytes / self-modifying code.
  size_t smc_candidates = 0;
  size_t write_execute_correlations = 0;
  size_t smc_comments = 0;
  size_t runtime_ranges_patched = 0;
  size_t runtime_bytes_patched = 0;
  size_t patches_skipped_conflict = 0;
  size_t patches_skipped_changed_db = 0;

  // Pointer tables and indirect-use correlation.
  size_t pointer_slot_candidates = 0;
  size_t pointer_slots_corroborated = 0;
  size_t pointer_clusters = 0;
  size_t pointer_clusters_correlated = 0;
  size_t pointer_offsets_created = 0;

  // Function/chunk recovery.
  size_t orphan_call_candidates = 0;
  size_t functions_promoted = 0;
  size_t tail_candidates = 0;
  size_t tails_appended = 0;

  // Comment policy (comments are never overwritten).
  size_t comments_added = 0;
  size_t comments_skipped_existing = 0;
};

// Apply runtime-derived enrichments. Main thread only.
//
// A final value must agree across at least two distinct (run_id, seed) pairs
// before it can create an item, promote a function/tail, or patch bytes. Runtime
// bytes are never patched unless cfg.apply_runtime_bytes is explicitly enabled.
RuntimeEnrichStats viy_runtime_enrich(const ProgramImage &img,
                                      const EmuEvents &events,
                                      const ViyConfig &cfg);

} // namespace viy
