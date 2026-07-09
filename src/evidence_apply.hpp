/* Guarded IDA consumer for producer-neutral evidence. */
#pragma once

#include <cstddef>

#include "evidence_store.hpp"
#include "ref_discovery.hpp"
#include "viy_config.hpp"

namespace viy {

struct EvidenceApplyStats
{
  RefStats refs;
  size_t functions_created = 0;
  size_t comments_added = 0;
  size_t records_considered = 0;
  size_t records_conflicted = 0;
  size_t records_below_policy = 0;
};

EvidenceApplyStats viy_apply_evidence(const analysis::EvidenceStore &store,
                                      const ViyConfig &cfg);

} // namespace viy
