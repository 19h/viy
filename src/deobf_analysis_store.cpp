/* IDA-free contradiction-gated EvidenceStore adapter. */
#include "deobf_analysis.hpp"

#include "evidence_store.hpp"

#include <utility>

namespace viy {
namespace {

bool observation_in_view(const analysis::Evidence &evidence,
                         uint64_t active_generation)
{
  return evidence.proof == analysis::ProofKind::UserAsserted
      || active_generation == 0
      || evidence.scope.generation == active_generation;
}

} // anonymous namespace

DeobfEvidenceStoreSink::DeobfEvidenceStoreSink(
    analysis::EvidenceStore &store)
  : store_(store)
{
}

DeobfEvidenceStoreSink::~DeobfEvidenceStoreSink() = default;

void DeobfEvidenceStoreSink::reset_report()
{
  report_ = {};
  last_error_.clear();
}

void DeobfEvidenceStoreSink::set_active_generation(uint64_t generation)
{
  active_generation_ = generation;
}

bool DeobfEvidenceStoreSink::emit_deobf_fact(
    const analysis::AnalysisFact &fact)
{
  analysis::AnalysisFact normalized = fact;
  std::string error;
  if ( !analysis::normalize_fact(normalized, &error) )
  {
    ++report_.rejected_invalid;
    last_error_ = std::move(error);
    return false;
  }

  if (observation_in_view(normalized.evidence, active_generation_))
  {
    const auto conflict = store_.new_contradiction(normalized.payload, active_generation_);
    if (conflict)
    {
      ++report_.contradictions_suppressed;
      last_error_ = conflict->explanation;
      return false;
    }
  }

  const analysis::AddResult added = store_.add(std::move(normalized));
  switch ( added.disposition )
  {
    case analysis::AddDisposition::InsertedRecord:
      ++report_.inserted_records;
      break;
    case analysis::AddDisposition::AddedObservation:
      ++report_.added_observations;
      break;
    case analysis::AddDisposition::DuplicateObservation:
      ++report_.duplicate_observations;
      break;
    case analysis::AddDisposition::RejectedInvalid:
      ++report_.rejected_invalid;
      last_error_ = added.error;
      return false;
  }
  return true;
}

} // namespace viy
