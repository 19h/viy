#include "analysis_facts.hpp"
#include "evidence_store.hpp"
#include "hexrays_bridge.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

using namespace viy;
using namespace viy::analysis;

namespace {

int failures = 0;

void expect(bool condition, const std::string &message)
{
  if ( !condition )
  {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

Evidence dynamic_evidence(uint64_t run, uint16_t confidence = 9300)
{
  Evidence evidence;
  evidence.producer = "test.emulator";
  evidence.method = "concrete";
  evidence.proof = ProofKind::Observed;
  evidence.confidence = confidence;
  evidence.scope.run_id = run;
  evidence.scope.seed = run * 17;
  evidence.scope.function_start = 0x1000;
  evidence.scope.function_end = 0x1100;
  evidence.support_addresses = {0x1010};
  return evidence;
}

Evidence static_evidence(uint16_t confidence = 9300)
{
  Evidence evidence = dynamic_evidence(1, confidence);
  evidence.producer = "test.static";
  evidence.method = "proof";
  evidence.proof = ProofKind::StaticProof;
  evidence.scope.run_id.reset();
  evidence.scope.seed.reset();
  return evidence;
}

void add(EvidenceStore &store, FactPayload payload, Evidence evidence)
{
  const AddResult result = store.add(AnalysisFact{std::move(payload),
                                                   std::move(evidence)});
  expect(result.disposition != AddDisposition::RejectedInvalid,
         "test fixture is accepted by EvidenceStore: " + result.error);
}

bool contains_text(const std::vector<HexRaysEvidenceAnnotation> &annotations,
                   const std::string &needle)
{
  return std::any_of(annotations.begin(), annotations.end(),
    [&](const HexRaysEvidenceAnnotation &annotation) {
      return annotation.text.find(needle) != std::string::npos;
    });
}

void test_confidence_and_corroboration_policy()
{
  EvidenceStore store;
  add(store,
      FunctionTraitFact{0x1000, FunctionTraitKind::NoReturn,
                        TraitValue::none()},
      static_evidence());
  add(store,
      RegisterValueFact{0x1010, RegisterStatePoint::BeforeInstruction,
                        "rax", {0x34, 0x12}},
      dynamic_evidence(10));
  add(store,
      MemoryAccessFact{0x1020, 0x5000, 4, MemoryAccessKind::Read},
      static_evidence(8000));

  HexRaysBridgeStats before;
  auto annotations = viy_build_hexrays_annotations(store, {}, &before);
  expect(annotations.size() == 1 && contains_text(annotations, "does not return"),
         "high-confidence static proof is shown while one run and low proof are withheld");
  expect(before.records_considered == 3 && before.records_accepted == 1
      && before.records_below_policy == 2,
         "selection statistics account for every evidence record");

  add(store,
      RegisterValueFact{0x1010, RegisterStatePoint::BeforeInstruction,
                        "rax", {0x34, 0x12}},
      dynamic_evidence(11));
  annotations = viy_build_hexrays_annotations(store);
  expect(annotations.size() == 2 && contains_text(annotations, "rax = 34 12"),
         "same concrete value from two explicit runs is exposed as a hint");

  HexRaysBridgeOptions unsafe;
  unsafe.minimum_distinct_runs = 1;
  EvidenceStore one_run;
  add(one_run,
      CodeTargetFact{0x1030, 0x2000, CodeTargetKind::Call, false},
      dynamic_evidence(1));
  expect(viy_build_hexrays_annotations(one_run, unsafe).empty(),
         "runtime policy cannot be weakened below two distinct runs");
}

void test_conflicts_and_non_observation_are_suppressed()
{
  EvidenceStore store;
  add(store, CodeTargetFact{0x1040, 0x2000, CodeTargetKind::Jump, true},
      static_evidence());
  add(store, CodeTargetFact{0x1040, 0x2100, CodeTargetKind::Jump, false},
      static_evidence());
  add(store,
      BranchReachabilityFact{0x1050, 0x1060, Reachability::NotObserved},
      static_evidence());

  HexRaysBridgeStats stats;
  const auto annotations = viy_build_hexrays_annotations(store, {}, &stats);
  expect(annotations.empty(),
         "contradictory targets and mere non-observation never reach the decompiler");
  expect(stats.records_conflicted == 2 && stats.records_accepted == 0,
         "both sides of a target conflict are gated");
}

void test_deterministic_rendering_and_scopes()
{
  EvidenceStore store;
  const FactPayload memory = MemoryValueFact{
    0x1018, 0x7000, MemoryAccessKind::Read,
    {0, 1, 2, 3, 4, 5}};
  add(store, memory, dynamic_evidence(3));
  add(store, memory, dynamic_evidence(4));
  add(store,
      CallObservationFact{0x1010, Address{0x3000}, CallKind::Call,
                          CallResult::Returned, {}, {}},
      static_evidence());

  HexRaysBridgeOptions options;
  options.maximum_value_bytes = 3;
  const auto first = viy_build_hexrays_annotations(store, options);
  const auto second = viy_build_hexrays_annotations(store, options);
  expect(first.size() == 2 && second.size() == first.size(),
         "accepted annotations have stable cardinality");
  expect(first[0].address == 0x1010 && first[1].address == 0x1018
      && first[1].text.find("00 01 02 ... (6 bytes)") != std::string::npos,
         "annotations are address-sorted and concrete byte output is bounded");
  expect(first[0].function_starts == std::vector<uint64_t>{0x1000}
      && first[1].function_starts == std::vector<uint64_t>{0x1000},
         "high-confidence provenance retains function scope");
  expect(first[0].text == second[0].text && first[1].text == second[1].text,
         "rendering is deterministic across repeated snapshots");
}

void test_sdk_disabled_lifecycle()
{
#if defined(VIY_WITH_HEXRAYS_SDK) && !VIY_WITH_HEXRAYS_SDK
  HexRaysEvidenceBridge bridge;
  std::string reason;
  expect(!HexRaysEvidenceBridge::compiled_with_hexrays_sdk(),
         "disabled build reports that no Hex-Rays SDK is compiled in");
  expect(!bridge.start({}, &reason) && !bridge.installed() && !reason.empty(),
         "disabled bridge fails closed with a useful reason");
  bridge.stop();
#endif
}

} // namespace

int main()
{
  test_confidence_and_corroboration_policy();
  test_conflicts_and_non_observation_are_suppressed();
  test_deterministic_rendering_and_scopes();
  test_sdk_disabled_lifecycle();
  if ( failures != 0 )
  {
    std::cerr << failures << " Hex-Rays bridge test(s) failed\n";
    return 1;
  }
  std::cout << "Hex-Rays bridge policy tests passed\n";
  return 0;
}
