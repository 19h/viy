#include "evidence_lifecycle.hpp"

#include <limits>
#include <utility>

namespace viy {
namespace analysis {

void EvidenceGenerationAllocator::seed(const EvidenceStore &history)
{
  used_.clear();
  for ( const AnalysisFact &fact : history.flattened_facts() )
    used_.insert(fact.evidence.scope.generation);

  cursor_ = 1;
  if ( !used_.empty() )
  {
    const uint64_t largest = *used_.rbegin();
    if ( largest != std::numeric_limits<uint64_t>::max() )
      cursor_ = largest + 1;
  }
}

uint64_t EvidenceGenerationAllocator::allocate()
{
  uint64_t candidate = cursor_ == 0 ? 1 : cursor_;
  while ( used_.find(candidate) != used_.end() )
  {
    candidate = candidate == std::numeric_limits<uint64_t>::max()
              ? 1 : candidate + 1;
  }
  used_.insert(candidate);
  cursor_ = candidate == std::numeric_limits<uint64_t>::max()
          ? 1 : candidate + 1;
  return candidate;
}

bool ActiveEvidencePolicy::is_active(const AnalysisFact &fact) const
{
  const Evidence &observation = fact.evidence;
  if ( observation.proof == ProofKind::UserAsserted )
    return true;

  const bool complete_provider = observation.producer == "viy.native.ida"
                              || observation.producer == "viy.deobf.ida";
  if ( complete_provider )
  {
    if ( provider_generation == 0
      || observation.scope.generation != provider_generation )
    {
      return false;
    }
    if ( !observation.scope.function_start.has_value() )
      return true;
    return provider_functions.find(*observation.scope.function_start)
        != provider_functions.end();
  }

  if ( !observation.scope.function_start.has_value() )
    return false;
  const auto expected = function_generations.find(
      *observation.scope.function_start);
  return expected != function_generations.end()
      && observation.scope.generation == expected->second;
}

EvidenceStore ActiveEvidencePolicy::view(const EvidenceStore &history) const
{
  EvidenceStore active;
  for ( AnalysisFact fact : history.flattened_facts() )
    if ( is_active(fact) )
      (void)active.add(std::move(fact));
  return active;
}

} // namespace analysis
} // namespace viy
