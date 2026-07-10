/*
 * Pure policy for deciding which producer-neutral facts may mutate an IDB.
 *
 * This layer deliberately has no IDA SDK dependency.  The IDA consumer builds
 * a plan here, then performs only the actions named by that plan on the main
 * thread.  Keeping conflict handling and trust thresholds here makes the
 * safety boundary directly testable.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "evidence_store.hpp"

namespace viy {
namespace analysis {

constexpr uint16_t kAutomaticProofConfidence = 9000;
constexpr uint16_t kCorroboratedRunConfidence = 8000;
constexpr size_t kCorroboratedRunFloor = 2;
constexpr uint16_t kFunctionCandidateStaticConfidence = 7500;

struct EvidenceApplyPolicy
{
  bool allow_function_recovery = true;
  bool allow_unreachable_comments = true;
};

enum class EvidenceActionKind : uint8_t
{
  None = 0,
  AddCallReference,
  AddJumpReference,
  CreateFunction,
  CommentProvenUnreachable,
};

enum class EvidenceDecisionReason : uint8_t
{
  Actionable = 1,
  Contradicted,
  BelowTrustThreshold,
  DisabledByConfiguration,
  UnsupportedTargetKind,
  UnsupportedPayloadKind,
  NonActionableReachability,
};

struct EvidenceApplyDecision
{
  FactPayload payload;
  EvidenceActionKind action = EvidenceActionKind::None;
  EvidenceDecisionReason reason = EvidenceDecisionReason::UnsupportedPayloadKind;
};

struct EvidenceApplyPlan
{
  // Exactly one decision per canonical EvidenceRecord in the input store, in
  // the store's deterministic record order.
  std::vector<EvidenceApplyDecision> decisions;
  size_t contradiction_suppressed = 0;
  size_t below_trust_threshold = 0;
  size_t disabled_by_configuration = 0;
  ContradictionScanStats contradiction_scan;
};

// Strong proof is sufficient by itself.  Otherwise, observations must clear
// the confidence floor in at least two distinct explicit run IDs.  Seeds do
// not substitute for runs.
bool evidence_is_automatically_actionable(const EvidenceRecord &record);

// Function discovery admits a lower-confidence static proof, then falls back
// to the same cross-run corroboration rule as other automatic actions.
bool function_candidate_is_actionable(const EvidenceRecord &record);

// Detect the exact contradiction-participant set across the complete store and
// produce a deterministic mutation plan. Contradictions suppress every
// participating payload; Variation and Ambiguity remain in the ledger but are
// intentionally absent from the automatic-application scan.
EvidenceApplyPlan plan_evidence_application(
  const EvidenceStore &store,
  const EvidenceApplyPolicy &policy = {});

} // namespace analysis
} // namespace viy
