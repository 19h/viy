/* Guarded IDA consumer for producer-neutral evidence. */
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>

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
  size_t conflict_relations_examined = 0;
  size_t conflict_digests_computed = 0;
};

enum class EvidenceApplyProgressStage : uint8_t
{
  PLANNING = 0,
  MUTATING,
  COMPLETE,
};

struct EvidenceApplyProgress
{
  EvidenceApplyProgressStage stage = EvidenceApplyProgressStage::PLANNING;
  size_t records_completed = 0;
  size_t records_total = 0;
  size_t records_conflicted = 0;
  size_t records_below_policy = 0;
  bool stage_boundary = false;
};

using EvidenceApplyProgressCallback =
    std::function<void(const EvidenceApplyProgress &)>;

EvidenceApplyStats viy_apply_evidence(const analysis::EvidenceStore &store,
                                      const ViyConfig &cfg,
                                      const EvidenceApplyProgressCallback &progress = {});

} // namespace viy
