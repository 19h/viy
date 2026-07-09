/* IDA-free contradiction-gated EvidenceStore adapter. */
#include "deobf_analysis.hpp"

#include "evidence_store.hpp"

#include <algorithm>
#include <utility>
#include <vector>

namespace viy {
namespace {

bool observation_in_view(const analysis::Evidence &evidence,
                         uint64_t active_generation)
{
  return evidence.proof == analysis::ProofKind::UserAsserted
      || active_generation == 0
      || evidence.scope.generation == active_generation;
}

analysis::EvidenceStore contradiction_view(
    const analysis::EvidenceStore &source,
    uint64_t active_generation)
{
  analysis::EvidenceStore current;
  for ( analysis::AnalysisFact candidate : source.flattened_facts() )
  {
    if ( observation_in_view(candidate.evidence, active_generation) )
    {
      (void)current.add(std::move(candidate));
    }
  }
  return current;
}

bool same_conflict(const analysis::EvidenceConflict &lhs,
                   const analysis::EvidenceConflict &rhs)
{
  return !analysis::conflict_less(lhs, rhs)
      && !analysis::conflict_less(rhs, lhs);
}

bool conflict_involves(const analysis::EvidenceConflict &conflict,
                       const analysis::FactDigest &digest)
{
  return conflict.severity == analysis::ConflictSeverity::Contradiction
      && (conflict.left == digest || conflict.right == digest);
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

  analysis::FactDigest digest;
  if ( !analysis::stable_digest(normalized.payload, digest, &error) )
  {
    ++report_.rejected_invalid;
    last_error_ = std::move(error);
    return false;
  }

  analysis::EvidenceStore prospective = store_;
  const analysis::AddResult staged = prospective.add(normalized);
  if ( staged.disposition == analysis::AddDisposition::RejectedInvalid )
  {
    ++report_.rejected_invalid;
    last_error_ = staged.error;
    return false;
  }

  const bool candidate_is_active =
      observation_in_view(normalized.evidence, active_generation_);
  if ( candidate_is_active
    && staged.disposition != analysis::AddDisposition::DuplicateObservation )
  {
    // Conflict identity is payload-based, but membership in the current view
    // is observation-based. Adding a current observation to a payload that
    // existed only historically can therefore introduce a contradiction and
    // must not bypass staging. Conversely, an observation that merely
    // corroborates a payload already conflicting in the active view introduces
    // nothing new.
    const analysis::EvidenceRecord *existing = store_.find(normalized.payload);
    const bool payload_was_active = existing != nullptr
        && std::any_of(
            existing->observations.begin(), existing->observations.end(),
            [&](const analysis::Evidence &observation)
            { return observation_in_view(observation, active_generation_); });
    const std::vector<analysis::EvidenceConflict> before = payload_was_active
        ? contradiction_view(store_, active_generation_).detect_conflicts()
        : std::vector<analysis::EvidenceConflict>{};
    const std::vector<analysis::EvidenceConflict> after =
        contradiction_view(prospective, active_generation_).detect_conflicts();
    for ( const analysis::EvidenceConflict &conflict : after )
    {
      if ( !conflict_involves(conflict, digest) )
        continue;
      const bool existed = std::any_of(
          before.begin(), before.end(),
          [&](const analysis::EvidenceConflict &prior)
          { return same_conflict(prior, conflict); });
      if ( !existed )
      {
        ++report_.contradictions_suppressed;
        last_error_ = conflict.explanation;
        return false;
      }
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
