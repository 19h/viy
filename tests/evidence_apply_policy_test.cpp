#include "analysis_facts.hpp"
#include "evidence_apply_policy.hpp"
#include "evidence_store.hpp"

#include <cstdint>
#include <iostream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace viy::analysis;

namespace {

int failures = 0;

void expect(bool condition, const std::string &message)
{
  if (!condition)
  {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

Evidence evidence(ProofKind proof,
                  uint16_t confidence,
                  std::optional<uint64_t> run = std::nullopt,
                  std::optional<uint64_t> seed = std::nullopt,
                  std::string producer = "policy.test")
{
  Evidence result;
  result.producer = std::move(producer);
  result.method = "classification";
  result.proof = proof;
  result.confidence = confidence;
  result.scope.run_id = run;
  result.scope.seed = seed;
  return result;
}

void add(EvidenceStore &store, const FactPayload &payload, Evidence proof,
         const std::string &message)
{
  const AddResult result = store.add(AnalysisFact{payload, std::move(proof)});
  expect(result.disposition == AddDisposition::InsertedRecord ||
           result.disposition == AddDisposition::AddedObservation,
         message + (result.error.empty() ? std::string() : ": " + result.error));
}

const EvidenceApplyDecision *find_decision(const EvidenceApplyPlan &plan,
                                           const FactPayload &payload)
{
  for (const EvidenceApplyDecision &decision : plan.decisions)
    if (payload_equal(decision.payload, payload))
      return &decision;
  return nullptr;
}

void expect_decision(const EvidenceApplyPlan &plan,
                     const FactPayload &payload,
                     EvidenceActionKind action,
                     EvidenceDecisionReason reason,
                     const std::string &message)
{
  const EvidenceApplyDecision *decision = find_decision(plan, payload);
  expect(decision != nullptr, message + " has a decision");
  if (decision == nullptr)
    return;
  expect(decision->action == action, message + " has the expected action");
  expect(decision->reason == reason, message + " has the expected reason");
}

FactPayload call_target(Address from = 0x1010, Address target = 0x3000,
                        bool unique = false)
{
  return CodeTargetFact{from, target, CodeTargetKind::Call, unique};
}

EvidenceApplyPlan plan_one(const FactPayload &payload, Evidence proof,
                           const EvidenceApplyPolicy &policy = {})
{
  EvidenceStore store;
  add(store, payload, std::move(proof), "single-record fixture is accepted");
  return plan_evidence_application(store, policy);
}

void test_every_payload_kind()
{
  DispatchMapFact dispatch;
  dispatch.site = 0x1700;
  dispatch.cases = {{uint64_t{0}, 0x1710}, {uint64_t{1}, 0x1720}};
  dispatch.complete = false;

  CallObservationFact observation;
  observation.source = 0x1c00;
  observation.target = 0x3000;
  observation.kind = CallKind::Call;
  observation.result = CallResult::Returned;

  const std::vector<std::pair<FactPayload, EvidenceActionKind>> fixtures = {
    {CodeTargetFact{0x1000, 0x3000, CodeTargetKind::Call, false},
     EvidenceActionKind::AddCallReference},
    {BranchReachabilityFact{0x1100, 0x1110,
                            Reachability::ProvenUnreachable},
     EvidenceActionKind::CommentProvenUnreachable},
    {MemoryAccessFact{0x1200, 0x4000, 4, MemoryAccessKind::Read},
     EvidenceActionKind::None},
    {MemoryValueFact{0x1300, 0x4010, MemoryAccessKind::Write, {1, 2}},
     EvidenceActionKind::None},
    {StringCandidateFact{0x4020, StringEncoding::Ascii, {'o', 'k'}, "ok", true},
     EvidenceActionKind::None},
    {FunctionCandidateFact{0x1400, Address{0x1450},
                           FunctionCandidateKind::CallTarget},
     EvidenceActionKind::CreateFunction},
    {FunctionTraitFact{0x1400, FunctionTraitKind::Returns, TraitValue::none()},
     EvidenceActionKind::None},
    {CodeRegionFact{0x1500, 0x1510, CodeRegionKind::Code},
     EvidenceActionKind::None},
    {dispatch, EvidenceActionKind::None},
    {CfgCandidateFact{0x1800, 0x1810, CfgEdgeKind::TrueBranch,
                      Reachability::Reached},
     EvidenceActionKind::None},
    {FunctionOutcomeFact{0x1900, FunctionStopKind::Returned, Address{0x19ff},
                         int64_t{8}, uint64_t{20}},
     EvidenceActionKind::None},
    {RegisterValueFact{0x1a00, RegisterStatePoint::AfterInstruction,
                       "rax", {0x34, 0x12}},
     EvidenceActionKind::None},
    {observation, EvidenceActionKind::None},
  };

  EvidenceStore store;
  for (const auto &fixture : fixtures)
  {
    add(store, fixture.first,
        evidence(ProofKind::StaticProof, kAutomaticProofConfidence),
        "payload-kind fixture is accepted");
  }
  const EvidenceApplyPlan plan = plan_evidence_application(store);
  expect(fixtures.size() == 13, "all thirteen payload variants are enumerated");
  expect(plan.decisions.size() == fixtures.size(),
         "one policy decision is produced for every payload variant");

  for (const auto &fixture : fixtures)
  {
    const bool actionable = fixture.second != EvidenceActionKind::None;
    expect_decision(plan, fixture.first, fixture.second,
                    actionable ? EvidenceDecisionReason::Actionable
                               : EvidenceDecisionReason::UnsupportedPayloadKind,
                    std::string("payload ") + fact_kind_name(fact_kind(fixture.first)));
  }
}

void test_code_target_kinds()
{
  const std::vector<std::pair<CodeTargetKind, EvidenceActionKind>> supported = {
    {CodeTargetKind::Call, EvidenceActionKind::AddCallReference},
    {CodeTargetKind::Jump, EvidenceActionKind::AddJumpReference},
    {CodeTargetKind::TableEntry, EvidenceActionKind::AddJumpReference},
  };
  Address from = 0x2000;
  for (const auto &fixture : supported)
  {
    const FactPayload payload = CodeTargetFact{from, from + 0x100,
                                               fixture.first, false};
    const EvidenceApplyPlan plan = plan_one(
      payload, evidence(ProofKind::StaticProof, kAutomaticProofConfidence));
    expect_decision(plan, payload, fixture.second,
                    EvidenceDecisionReason::Actionable,
                    "supported code-target kind");
    from += 0x10;
  }

  const std::vector<CodeTargetKind> unsupported = {
    CodeTargetKind::Unknown,
    CodeTargetKind::Fallthrough,
    CodeTargetKind::Return,
    CodeTargetKind::Exception,
  };
  for (CodeTargetKind kind : unsupported)
  {
    const FactPayload payload = CodeTargetFact{from, from + 0x100, kind, false};
    const EvidenceApplyPlan plan = plan_one(
      payload, evidence(ProofKind::UserAsserted, kMaxConfidence));
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::UnsupportedTargetKind,
                    "unsupported code-target kind");
    from += 0x10;
  }
}

void test_strong_proof_thresholds()
{
  const std::vector<ProofKind> trusted = {
    ProofKind::StaticProof,
    ProofKind::SymbolicProof,
    ProofKind::UserAsserted,
  };
  Address from = 0x3000;
  for (ProofKind proof : trusted)
  {
    const FactPayload payload = call_target(from, from + 0x200);
    EvidenceApplyPlan plan = plan_one(
      payload, evidence(proof, kAutomaticProofConfidence - 1));
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::BelowTrustThreshold,
                    "trusted proof immediately below 9000");
    expect(plan.below_trust_threshold == 1,
           "below-threshold trusted proof is counted");

    plan = plan_one(payload, evidence(proof, kAutomaticProofConfidence));
    expect_decision(plan, payload, EvidenceActionKind::AddCallReference,
                    EvidenceDecisionReason::Actionable,
                    "trusted proof at 9000");
    from += 0x10;
  }

  const std::vector<ProofKind> not_sufficient_alone = {
    ProofKind::Unknown,
    ProofKind::Observed,
    ProofKind::CrossRunCorroboration,
    ProofKind::Heuristic,
    ProofKind::Imported,
  };
  for (ProofKind proof : not_sufficient_alone)
  {
    const FactPayload payload = call_target(from, from + 0x200);
    const EvidenceApplyPlan plan = plan_one(payload,
      evidence(proof, kMaxConfidence, uint64_t{1}, uint64_t{1}));
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::BelowTrustThreshold,
                    "non-proof observation cannot authorize one-run mutation");
    from += 0x10;
  }
}

void test_dynamic_run_corroboration()
{
  const FactPayload payload = call_target(0x4000, 0x5000);

  {
    EvidenceStore store;
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 uint64_t{10}, uint64_t{7}),
        "first distinct-run observation is accepted");
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 uint64_t{11}, uint64_t{7}),
        "second distinct-run observation is accepted");
    const EvidenceApplyPlan plan = plan_evidence_application(store);
    expect_decision(plan, payload, EvidenceActionKind::AddCallReference,
                    EvidenceDecisionReason::Actionable,
                    "two distinct runs pass even with the same seed");
  }

  {
    EvidenceStore store;
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 uint64_t{20}, uint64_t{1}),
        "same-run seed-one observation is accepted");
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 uint64_t{20}, uint64_t{2}),
        "same-run seed-two observation is accepted");
    const EvidenceApplyPlan plan = plan_evidence_application(store);
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::BelowTrustThreshold,
                    "different seeds in one run do not manufacture corroboration");
  }

  {
    EvidenceStore store;
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence - 1,
                 uint64_t{30}, uint64_t{1}),
        "low-confidence run is accepted as evidence");
    add(store, payload,
        evidence(ProofKind::Observed, kMaxConfidence,
                 uint64_t{31}, uint64_t{2}),
        "high-confidence run is accepted as evidence");
    const EvidenceApplyPlan plan = plan_evidence_application(store);
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::BelowTrustThreshold,
                    "each of two corroborating runs must clear 8000");
  }

  {
    EvidenceStore store;
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 std::nullopt, uint64_t{1}),
        "unscoped observation is accepted");
    add(store, payload,
        evidence(ProofKind::Observed, kCorroboratedRunConfidence,
                 uint64_t{40}, uint64_t{2}),
        "single explicitly scoped run is accepted");
    const EvidenceApplyPlan plan = plan_evidence_application(store);
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::BelowTrustThreshold,
                    "an observation without a run ID is not a distinct run");
  }
}

void test_function_candidate_threshold_and_gate()
{
  const FactPayload candidate = FunctionCandidateFact{
    0x6000, Address{0x6100}, FunctionCandidateKind::OrphanChunk};

  EvidenceApplyPlan plan = plan_one(candidate,
    evidence(ProofKind::StaticProof,
             kFunctionCandidateStaticConfidence - 1));
  expect_decision(plan, candidate, EvidenceActionKind::None,
                  EvidenceDecisionReason::BelowTrustThreshold,
                  "function candidate immediately below 7500");

  plan = plan_one(candidate,
    evidence(ProofKind::StaticProof, kFunctionCandidateStaticConfidence));
  expect_decision(plan, candidate, EvidenceActionKind::CreateFunction,
                  EvidenceDecisionReason::Actionable,
                  "function candidate at the 7500 static threshold");

  EvidenceStore corroborated;
  add(corroborated, candidate,
      evidence(ProofKind::Observed, kCorroboratedRunConfidence,
               uint64_t{1}, uint64_t{1}),
      "first candidate run is accepted");
  add(corroborated, candidate,
      evidence(ProofKind::Observed, kCorroboratedRunConfidence,
               uint64_t{2}, uint64_t{2}),
      "second candidate run is accepted");
  plan = plan_evidence_application(corroborated);
  expect_decision(plan, candidate, EvidenceActionKind::CreateFunction,
                  EvidenceDecisionReason::Actionable,
                  "function candidates also admit two-run corroboration");

  EvidenceApplyPolicy disabled;
  disabled.allow_function_recovery = false;
  plan = plan_one(candidate,
    evidence(ProofKind::StaticProof, kMaxConfidence), disabled);
  expect_decision(plan, candidate, EvidenceActionKind::None,
                  EvidenceDecisionReason::DisabledByConfiguration,
                  "function-recovery gate suppresses a trusted candidate");
  expect(plan.disabled_by_configuration == 1,
         "disabled function candidate is counted separately from weak evidence");
}

void test_branch_state_and_comment_gate()
{
  const FactPayload unreachable = BranchReachabilityFact{
    0x7000, 0x7010, Reachability::ProvenUnreachable};
  EvidenceApplyPolicy disabled;
  disabled.allow_unreachable_comments = false;
  EvidenceApplyPlan plan = plan_one(unreachable,
    evidence(ProofKind::StaticProof, kAutomaticProofConfidence), disabled);
  expect_decision(plan, unreachable, EvidenceActionKind::None,
                  EvidenceDecisionReason::DisabledByConfiguration,
                  "comment gate suppresses proven-unreachable annotation");

  const std::vector<Reachability> non_actions = {
    Reachability::NotObserved,
    Reachability::Reached,
  };
  for (Reachability state : non_actions)
  {
    const FactPayload payload = BranchReachabilityFact{0x7100, 0x7110, state};
    plan = plan_one(payload,
      evidence(ProofKind::StaticProof, kAutomaticProofConfidence));
    expect_decision(plan, payload, EvidenceActionKind::None,
                    EvidenceDecisionReason::NonActionableReachability,
                    "non-proof reachability state is retained without mutation");
  }

  const FactPayload target = call_target(0x7200, 0x7300);
  plan = plan_one(target,
    evidence(ProofKind::StaticProof, kAutomaticProofConfidence), disabled);
  expect_decision(plan, target, EvidenceActionKind::AddCallReference,
                  EvidenceDecisionReason::Actionable,
                  "comment/function gates do not disable code-target actions");
}

void test_contradiction_suppression()
{
  const FactPayload left = call_target(0x8000, 0x9000, true);
  const FactPayload right = call_target(0x8000, 0xa000, true);
  const FactPayload independent = call_target(0x8010, 0xb000, true);
  EvidenceStore store;
  add(store, left, evidence(ProofKind::StaticProof, kMaxConfidence),
      "left unique target is accepted");
  add(store, right, evidence(ProofKind::StaticProof, kMaxConfidence),
      "right unique target is accepted");
  add(store, independent, evidence(ProofKind::StaticProof, kMaxConfidence),
      "independent target is accepted");

  const EvidenceApplyPlan plan = plan_evidence_application(store);
  expect(plan.contradiction_suppressed == 2,
         "both payloads participating in a contradiction are suppressed");
  expect_decision(plan, left, EvidenceActionKind::None,
                  EvidenceDecisionReason::Contradicted,
                  "left contradictory target");
  expect_decision(plan, right, EvidenceActionKind::None,
                  EvidenceDecisionReason::Contradicted,
                  "right contradictory target");
  expect_decision(plan, independent, EvidenceActionKind::AddCallReference,
                  EvidenceDecisionReason::Actionable,
                  "unrelated trusted target survives another record's contradiction");

  const FactPayload reached = BranchReachabilityFact{
    0x8100, 0x8110, Reachability::Reached};
  const FactPayload unreachable = BranchReachabilityFact{
    0x8100, 0x8110, Reachability::ProvenUnreachable};
  EvidenceStore branches;
  add(branches, reached, evidence(ProofKind::StaticProof, kMaxConfidence),
      "reached branch fact is accepted");
  add(branches, unreachable, evidence(ProofKind::StaticProof, kMaxConfidence),
      "unreachable branch proof is accepted");
  const EvidenceApplyPlan branch_plan = plan_evidence_application(branches);
  expect(branch_plan.contradiction_suppressed == 2,
         "reachable/unreachable contradiction suppresses both branch records");
  expect_decision(branch_plan, unreachable, EvidenceActionKind::None,
                  EvidenceDecisionReason::Contradicted,
                  "contradicted unreachable proof cannot produce a comment");
}

void test_ambiguity_and_variation_do_not_suppress()
{
  const FactPayload first_candidate = FunctionCandidateFact{
    0xc000, Address{0xc100}, FunctionCandidateKind::OrphanChunk};
  const FactPayload second_candidate = FunctionCandidateFact{
    0xc000, Address{0xc200}, FunctionCandidateKind::OrphanChunk};
  EvidenceStore ambiguous;
  add(ambiguous, first_candidate,
      evidence(ProofKind::StaticProof, kFunctionCandidateStaticConfidence),
      "first ambiguous candidate is accepted");
  add(ambiguous, second_candidate,
      evidence(ProofKind::StaticProof, kFunctionCandidateStaticConfidence),
      "second ambiguous candidate is accepted");
  const std::vector<EvidenceConflict> ambiguity = ambiguous.detect_conflicts();
  expect(ambiguity.size() == 1 &&
           ambiguity.front().severity == ConflictSeverity::Ambiguity,
         "candidate-end disagreement is classified as ambiguity");
  const EvidenceApplyPlan ambiguous_plan = plan_evidence_application(ambiguous);
  expect(ambiguous_plan.contradiction_suppressed == 0,
         "ambiguity does not enter the contradiction suppression set");
  expect_decision(ambiguous_plan, first_candidate,
                  EvidenceActionKind::CreateFunction,
                  EvidenceDecisionReason::Actionable,
                  "first ambiguous candidate remains policy-actionable");
  expect_decision(ambiguous_plan, second_candidate,
                  EvidenceActionKind::CreateFunction,
                  EvidenceDecisionReason::Actionable,
                  "second ambiguous candidate remains policy-actionable");

  const FactPayload first_value = MemoryValueFact{
    0xd000, 0xe000, MemoryAccessKind::Read, {1}};
  const FactPayload second_value = MemoryValueFact{
    0xd000, 0xe000, MemoryAccessKind::Read, {2}};
  EvidenceStore varying;
  add(varying, first_value, evidence(ProofKind::Observed, kMaxConfidence,
                                     uint64_t{1}, uint64_t{1}),
      "first varying memory value is accepted");
  add(varying, second_value, evidence(ProofKind::Observed, kMaxConfidence,
                                      uint64_t{2}, uint64_t{2}),
      "second varying memory value is accepted");
  const std::vector<EvidenceConflict> variation = varying.detect_conflicts();
  expect(variation.size() == 1 &&
           variation.front().severity == ConflictSeverity::Variation,
         "runtime memory disagreement is classified as variation");
  const EvidenceApplyPlan varying_plan = plan_evidence_application(varying);
  expect(varying_plan.contradiction_suppressed == 0,
         "variation does not enter the contradiction suppression set");
  expect_decision(varying_plan, first_value, EvidenceActionKind::None,
                  EvidenceDecisionReason::UnsupportedPayloadKind,
                  "first variation remains a retained non-action payload");
  expect_decision(varying_plan, second_value, EvidenceActionKind::None,
                  EvidenceDecisionReason::UnsupportedPayloadKind,
                  "second variation remains a retained non-action payload");
}

} // namespace

int main()
{
  test_every_payload_kind();
  test_code_target_kinds();
  test_strong_proof_thresholds();
  test_dynamic_run_corroboration();
  test_function_candidate_threshold_and_gate();
  test_branch_state_and_comment_gate();
  test_contradiction_suppression();
  test_ambiguity_and_variation_do_not_suppress();

  if (failures != 0)
  {
    std::cerr << failures << " evidence-apply policy assertion(s) failed\n";
    return 1;
  }
  std::cout << "evidence-apply policy tests passed\n";
  return 0;
}
