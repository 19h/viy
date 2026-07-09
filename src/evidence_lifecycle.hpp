/*
 * evidence_lifecycle.hpp -- persistence-safe generation allocation and the
 * exact active view used by mutating/presentation consumers.
 */
#pragma once

#include <cstdint>
#include <map>
#include <set>

#include "evidence_store.hpp"

namespace viy {
namespace analysis {

// Allocates identities that do not collide with any observation restored from
// the ledger (including hostile UINT64_MAX values). Numeric ordering is not an
// authority decision; ActiveEvidencePolicy compares exact identities.
class EvidenceGenerationAllocator
{
public:
  void seed(const EvidenceStore &history);
  uint64_t allocate();

  const std::set<uint64_t> &used() const { return used_; }

private:
  std::set<uint64_t> used_;
  uint64_t cursor_ = 1;
};

struct ActiveEvidencePolicy
{
  // Native/deobf providers perform complete current-IDB scans at this one
  // generation. Their function-scoped facts must additionally belong to a
  // function included in that scan.
  uint64_t provider_generation = 0;
  std::set<Address> provider_functions;

  // All other computed producers are active only at the exact current
  // per-function semantic generation. Absence from this map retires facts for
  // removed or currently out-of-scope functions.
  std::map<Address, uint64_t> function_generations;

  bool is_active(const AnalysisFact &fact) const;
  EvidenceStore view(const EvidenceStore &history) const;
};

} // namespace analysis
} // namespace viy
