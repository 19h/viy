#include "evidence_apply_policy.hpp"

#include <set>
#include <utility>

namespace viy {
namespace analysis {

namespace {

bool has_strong_proof(const EvidenceRecord &record)
{
  for (const Evidence &evidence : record.observations)
  {
    const bool trusted_proof =
      evidence.proof == ProofKind::StaticProof ||
      evidence.proof == ProofKind::SymbolicProof ||
      evidence.proof == ProofKind::UserAsserted;
    if (trusted_proof && evidence.confidence >= kAutomaticProofConfidence)
      return true;
  }
  return false;
}

void account_decision(EvidenceApplyPlan &plan,
                      EvidenceDecisionReason reason)
{
  switch (reason)
  {
    case EvidenceDecisionReason::Contradicted:
      ++plan.contradiction_suppressed;
      break;
    case EvidenceDecisionReason::BelowTrustThreshold:
      ++plan.below_trust_threshold;
      break;
    case EvidenceDecisionReason::DisabledByConfiguration:
      ++plan.disabled_by_configuration;
      break;
    case EvidenceDecisionReason::Actionable:
    case EvidenceDecisionReason::UnsupportedTargetKind:
    case EvidenceDecisionReason::UnsupportedPayloadKind:
    case EvidenceDecisionReason::NonActionableReachability:
      break;
  }
}

EvidenceApplyDecision classify_record(const EvidenceRecord &record,
                                      bool contradicted,
                                      const EvidenceApplyPolicy &policy)
{
  EvidenceApplyDecision decision;
  decision.payload = record.payload;

  if (contradicted)
  {
    decision.reason = EvidenceDecisionReason::Contradicted;
    return decision;
  }

  if (const auto *target = std::get_if<CodeTargetFact>(&record.payload))
  {
    switch (target->kind)
    {
      case CodeTargetKind::Call:
        decision.action = EvidenceActionKind::AddCallReference;
        break;
      case CodeTargetKind::Jump:
      case CodeTargetKind::TableEntry:
        decision.action = EvidenceActionKind::AddJumpReference;
        break;
      case CodeTargetKind::Unknown:
      case CodeTargetKind::Fallthrough:
      case CodeTargetKind::Return:
      case CodeTargetKind::Exception:
        decision.reason = EvidenceDecisionReason::UnsupportedTargetKind;
        return decision;
    }
    if (!evidence_is_automatically_actionable(record))
    {
      decision.action = EvidenceActionKind::None;
      decision.reason = EvidenceDecisionReason::BelowTrustThreshold;
      return decision;
    }
    decision.reason = EvidenceDecisionReason::Actionable;
    return decision;
  }

  if (std::holds_alternative<FunctionCandidateFact>(record.payload))
  {
    if (!policy.allow_function_recovery)
    {
      decision.reason = EvidenceDecisionReason::DisabledByConfiguration;
      return decision;
    }
    if (!function_candidate_is_actionable(record))
    {
      decision.reason = EvidenceDecisionReason::BelowTrustThreshold;
      return decision;
    }
    decision.action = EvidenceActionKind::CreateFunction;
    decision.reason = EvidenceDecisionReason::Actionable;
    return decision;
  }

  if (const auto *reach = std::get_if<BranchReachabilityFact>(&record.payload))
  {
    if (reach->state != Reachability::ProvenUnreachable)
    {
      decision.reason = EvidenceDecisionReason::NonActionableReachability;
      return decision;
    }
    if (!policy.allow_unreachable_comments)
    {
      decision.reason = EvidenceDecisionReason::DisabledByConfiguration;
      return decision;
    }
    if (!evidence_is_automatically_actionable(record))
    {
      decision.reason = EvidenceDecisionReason::BelowTrustThreshold;
      return decision;
    }
    decision.action = EvidenceActionKind::CommentProvenUnreachable;
    decision.reason = EvidenceDecisionReason::Actionable;
    return decision;
  }

  decision.reason = EvidenceDecisionReason::UnsupportedPayloadKind;
  return decision;
}

} // namespace

bool evidence_is_automatically_actionable(const EvidenceRecord &record)
{
  return has_strong_proof(record) ||
         is_corroborated(record, kCorroboratedRunFloor, 1,
                         kCorroboratedRunConfidence);
}

bool function_candidate_is_actionable(const EvidenceRecord &record)
{
  for (const Evidence &evidence : record.observations)
  {
    if (evidence.proof == ProofKind::StaticProof &&
        evidence.confidence >= kFunctionCandidateStaticConfidence)
      return true;
  }
  return is_corroborated(record, kCorroboratedRunFloor, 1,
                         kCorroboratedRunConfidence);
}

EvidenceApplyPlan plan_evidence_application(const EvidenceStore &store,
                                            const EvidenceApplyPolicy &policy)
{
  EvidenceApplyPlan plan;
  const std::set<FactDigest> contradicted =
    store.contradicted_payload_digests(&plan.contradiction_scan);

  const std::vector<EvidenceRecord> records = store.records();
  plan.decisions.reserve(records.size());
  for (const EvidenceRecord &record : records)
  {
    FactDigest digest;
    // EvidenceStore rejects invalid payloads, so failure is unreachable.  A
    // failed digest must nevertheless fail closed instead of authorizing a
    // mutation from a record whose identity cannot be checked for conflict.
    const bool digest_ok = stable_digest(record.payload, digest, nullptr);
    const bool is_contradicted = !digest_ok || contradicted.count(digest) != 0;
    EvidenceApplyDecision decision = classify_record(record, is_contradicted,
                                                      policy);
    account_decision(plan, decision.reason);
    plan.decisions.push_back(std::move(decision));
  }
  return plan;
}

} // namespace analysis
} // namespace viy
