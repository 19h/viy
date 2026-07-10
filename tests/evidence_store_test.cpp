#include "analysis_facts.hpp"
#include "evidence_store.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <set>
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

Evidence evidence(uint64_t run,
                  uint64_t seed,
                  std::string producer = "test.rax",
                  std::string method = "emulate")
{
  Evidence result;
  result.producer = std::move(producer);
  result.method = std::move(method);
  result.proof = ProofKind::Observed;
  result.confidence = 9300;
  result.scope.run_id = run;
  result.scope.seed = seed;
  result.scope.function_start = 0x1000;
  result.scope.function_end = 0x1100;
  result.scope.generation = 0x100000002ULL;
  result.support_addresses = {0x1010, 0x1000, 0x1010};
  result.detail = "standalone evidence test";
  return result;
}

AnalysisFact observed(FactPayload payload, uint64_t run, uint64_t seed,
                      const std::string &producer = "test.rax")
{
  return AnalysisFact{std::move(payload), evidence(run, seed, producer)};
}

bool has_conflict(const std::vector<EvidenceConflict> &conflicts,
                  ConflictType type,
                  ConflictSeverity severity)
{
  return std::any_of(conflicts.begin(), conflicts.end(),
                     [&](const EvidenceConflict &conflict) {
                       return conflict.type == type && conflict.severity == severity;
                     });
}

void reseal_store_blob(std::vector<uint8_t> &blob)
{
  constexpr size_t digest_size = 32;
  expect(blob.size() >= digest_size, "store fixture is large enough to reseal");
  if (blob.size() < digest_size)
    return;
  const size_t envelope_size = blob.size() - digest_size;
  const std::vector<uint8_t> envelope(blob.begin(),
    blob.begin() + static_cast<std::ptrdiff_t>(envelope_size));
  const FactDigest digest = sha256_bytes(envelope);
  std::copy(digest.bytes.begin(), digest.bytes.end(),
            blob.begin() + static_cast<std::ptrdiff_t>(envelope_size));
}

class MemoryAdapter : public EvidencePersistenceAdapter
{
public:
  bool read_blob(std::vector<uint8_t> &out, std::string &error) const override
  {
    if (fail_reads)
    {
      error = "injected read failure";
      return false;
    }
    out = bytes;
    return true;
  }

  bool write_blob(const std::vector<uint8_t> &blob, std::string &error) override
  {
    if (fail_writes)
    {
      error = "injected write failure";
      return false;
    }
    bytes = blob;
    return true;
  }

  std::vector<uint8_t> bytes;
  bool fail_reads = false;
  bool fail_writes = false;
};

void test_sha256()
{
  const std::vector<uint8_t> empty;
  expect(sha256_bytes(empty).hex() ==
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
         "SHA-256 implementation matches the standard empty vector");
  const std::vector<uint8_t> abc{'a', 'b', 'c'};
  expect(sha256_bytes(abc).hex() ==
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
         "SHA-256 implementation matches the standard abc vector");
  const std::vector<uint8_t> million_a(1000000, static_cast<uint8_t>('a'));
  expect(sha256_bytes(million_a).hex() ==
           "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
         "SHA-256 implementation matches the standard million-a vector");
}

void test_every_payload_codec()
{
  static const char *expected_names[] = {
    "CodeTarget", "BranchReachability", "MemoryAccess", "MemoryValue",
    "StringCandidate", "FunctionCandidate", "FunctionTrait", "CodeRegion",
    "DispatchMap", "CfgCandidate", "FunctionOutcome", "RegisterValue",
    "CallObservation"};
  DispatchMapFact dispatch;
  dispatch.site = 0x1800;
  dispatch.cases = {{uint64_t{7}, 0x1900}, {uint64_t{1}, 0x1810},
                    {uint64_t{1}, 0x1810}, {std::nullopt, 0x1a00}};
  dispatch.default_target = 0x1b00;
  dispatch.complete = false;

  CallObservationFact call;
  call.source = 0x9000;
  call.target = 0xa000;
  call.kind = CallKind::Call;
  call.result = CallResult::Returned;
  call.arguments = {{1, "reg:x1", {0x22}}, {0, "reg:x0", {0x11}},
                    {0, "reg:x0", {0x11}}};
  call.returns = {{0, "reg:x0", {0x33}}};

  std::vector<FactPayload> payloads;
  payloads.emplace_back(CodeTargetFact{0x1000, 0x2000, CodeTargetKind::Call, true});
  payloads.emplace_back(BranchReachabilityFact{0x1010, 0x1020, Reachability::Reached});
  payloads.emplace_back(MemoryAccessFact{0x1030, 0x3000, 16, MemoryAccessKind::Read});
  payloads.emplace_back(MemoryValueFact{0x1040, 0x3010, MemoryAccessKind::Write,
                                        {0x00, 0xff, 0x42, 0x80}});
  payloads.emplace_back(StringCandidateFact{0x4000, StringEncoding::Utf8,
                                             {'h', 'i'}, "hi", true});
  payloads.emplace_back(FunctionCandidateFact{0x5000, Address{0x5100},
                                               FunctionCandidateKind::CallTarget});
  payloads.emplace_back(FunctionTraitFact{0x5000, FunctionTraitKind::StackDelta,
                                           TraitValue::signed_integer(-24)});
  payloads.emplace_back(CodeRegionFact{0x6000, 0x6100, CodeRegionKind::Code});
  payloads.emplace_back(dispatch);
  payloads.emplace_back(CfgCandidateFact{0x7000, 0x7010, CfgEdgeKind::TrueBranch,
                                          Reachability::Reached});
  payloads.emplace_back(FunctionOutcomeFact{0x8000, FunctionStopKind::Returned,
                                             Address{0x80ff}, int64_t{8}, uint64_t{99}});
  payloads.emplace_back(RegisterValueFact{0x8010,
                                           RegisterStatePoint::AfterInstruction,
                                           "x0", {0x78, 0x56, 0x34, 0x12}});
  payloads.emplace_back(call);

  expect(payloads.size() == 13, "the codec test covers all thirteen fact kinds");
  for (size_t i = 0; i != payloads.size(); ++i)
  {
    expect(std::string(fact_kind_name(fact_kind(payloads[i]))) == expected_names[i],
           "fact kind " + std::to_string(i) + " has a stable display name");
    std::vector<uint8_t> encoded;
    std::string error;
    expect(encode_payload(payloads[i], encoded, &error),
           "payload " + std::to_string(i) + " encodes: " + error);
    FactPayload decoded;
    expect(decode_payload(encoded, decoded, &error),
           "payload " + std::to_string(i) + " decodes: " + error);
    expect(payload_equal(payloads[i], decoded),
           "payload " + std::to_string(i) + " survives canonical round trip");

    FactDigest first, second;
    expect(stable_digest(payloads[i], first, &error) &&
           stable_digest(decoded, second, &error) && first == second,
           "payload " + std::to_string(i) + " has a stable semantic digest");

    AnalysisFact fact{payloads[i], evidence(i + 1, i * 3)};
    std::vector<uint8_t> fact_bytes;
    AnalysisFact decoded_fact;
    expect(encode_analysis_fact(fact, fact_bytes, &error) &&
           decode_analysis_fact(fact_bytes, decoded_fact, &error),
           "analysis fact " + std::to_string(i) + " round trips: " + error);
    expect(payload_equal(fact.payload, decoded_fact.payload) &&
           evidence_equal(fact.evidence, decoded_fact.evidence),
           "analysis fact " + std::to_string(i) + " retains payload and provenance");
    FactDigest evidence_digest, fact_digest;
    expect(stable_digest(fact.evidence, evidence_digest, &error) &&
             stable_digest(fact, fact_digest, &error) &&
             evidence_digest != fact_digest,
           "evidence and complete-fact digests are domain-separated");
  }
  expect(std::string(fact_kind_name(static_cast<FactKind>(0xff))) == "Invalid",
         "invalid fact-kind display is explicit");

  FactPayload normalized_dispatch = dispatch;
  std::string error;
  expect(normalize_payload(normalized_dispatch, &error), "dispatch normalizes");
  const auto &cases = std::get<DispatchMapFact>(normalized_dispatch).cases;
  expect(cases.size() == 3 && cases[0].selector == uint64_t{1} &&
           cases[1].selector == uint64_t{7} && !cases[2].selector.has_value(),
         "dispatch cases are sorted and exact duplicates are removed");

  FactPayload normalized_call = call;
  expect(normalize_payload(normalized_call, &error), "call observation normalizes");
  const auto &arguments = std::get<CallObservationFact>(normalized_call).arguments;
  expect(arguments.size() == 2 && arguments[0].ordinal == 0 &&
           arguments[1].ordinal == 1,
         "call arguments are sorted and exact duplicates are removed");
}

void test_validation()
{
  std::string error;
  AnalysisFact bad = observed(MemoryAccessFact{0x1000, 0x2000, 0,
                                               MemoryAccessKind::Read}, 1, 1);
  expect(!normalize_fact(bad, &error) && !error.empty(),
         "zero-sized memory access is rejected");

  bad = observed(CodeRegionFact{0x2000, 0x2000, CodeRegionKind::Code}, 1, 1);
  expect(!normalize_fact(bad, &error), "empty code region is rejected");

  FactPayload last_byte = MemoryAccessFact{0x1000,
    std::numeric_limits<Address>::max(), 1, MemoryAccessKind::Read};
  expect(normalize_payload(last_byte, &error),
         "a one-byte access at the final address is representable");
  FactPayload overflowing = MemoryAccessFact{0x1000,
    std::numeric_limits<Address>::max() - 1, 3, MemoryAccessKind::Read};
  expect(!normalize_payload(overflowing, &error),
         "an access extending beyond the address space is rejected");

  bad = observed(CodeTargetFact{0x1000, 0x2000, CodeTargetKind::Jump, false}, 1, 1);
  bad.evidence.producer.clear();
  expect(!normalize_fact(bad, &error), "empty producer id is rejected");

  bad = observed(CodeTargetFact{0x1000, 0x2000, CodeTargetKind::Jump, false}, 1, 1);
  bad.evidence.confidence = kMaxConfidence + 1;
  expect(!normalize_fact(bad, &error), "out-of-range confidence is rejected");

  DispatchMapFact ambiguous_in_one_fact;
  ambiguous_in_one_fact.site = 0x3000;
  ambiguous_in_one_fact.cases = {{uint64_t{1}, 0x3100}, {uint64_t{1}, 0x3200}};
  FactPayload dispatch = ambiguous_in_one_fact;
  expect(!normalize_payload(dispatch, &error),
         "one dispatch fact cannot map one known selector to two targets");

  Evidence scoped = evidence(1, 2);
  scoped.scope.function_start.reset();
  expect(!normalize_evidence(scoped, &error),
         "function end without start is rejected");

  AnalysisFact false_proof = observed(
    BranchReachabilityFact{0x1000, 0x1010, Reachability::ProvenUnreachable}, 1, 1);
  expect(!normalize_fact(false_proof, &error),
         "dynamic observation cannot masquerade as proof of unreachability");

  FactPayload malformed_utf8 = StringCandidateFact{
    0x4000, StringEncoding::Utf8, {0xc0, 0x80}, "", false};
  expect(!normalize_payload(malformed_utf8, &error),
         "overlong UTF-8 is rejected while arbitrary bytes remain representable as Bytes");

  FactPayload utf16le = StringCandidateFact{
    0x4100, StringEncoding::Utf16LE, {0x3d, 0xd8, 0x00, 0xde},
    "\xf0\x9f\x98\x80", true};
  FactPayload utf16be = StringCandidateFact{
    0x4200, StringEncoding::Utf16BE, {0xd8, 0x3d, 0xde, 0x00},
    "\xf0\x9f\x98\x80", true};
  FactPayload utf32le = StringCandidateFact{
    0x4300, StringEncoding::Utf32LE, {0x00, 0xf6, 0x01, 0x00},
    "\xf0\x9f\x98\x80", true};
  FactPayload utf32be = StringCandidateFact{
    0x4400, StringEncoding::Utf32BE, {0x00, 0x01, 0xf6, 0x00},
    "\xf0\x9f\x98\x80", true};
  expect(normalize_payload(utf16le, &error) && normalize_payload(utf16be, &error) &&
           normalize_payload(utf32le, &error) && normalize_payload(utf32be, &error),
         "well-formed UTF-16/UTF-32 candidates validate in both byte orders");
  FactPayload unpaired_surrogate = StringCandidateFact{
    0x4500, StringEncoding::Utf16LE, {0x00, 0xdc}, "", false};
  FactPayload oversized_codepoint = StringCandidateFact{
    0x4600, StringEncoding::Utf32LE, {0x00, 0x00, 0x11, 0x00}, "", false};
  expect(!normalize_payload(unpaired_surrogate, &error) &&
           !normalize_payload(oversized_codepoint, &error),
         "unpaired UTF-16 surrogates and out-of-range UTF-32 code points are rejected");

  FactPayload malformed_trait = FunctionTraitFact{
    0x5000, FunctionTraitKind::NoReturn, TraitValue::boolean(false)};
  expect(!normalize_payload(malformed_trait, &error),
         "presence-style function traits cannot carry contradictory boolean values");

  FactPayload wrapper_trait = FunctionTraitFact{
    0x5000, FunctionTraitKind::WrapperTarget,
    TraitValue::unsigned_integer(0x6000)};
  FactPayload convention_trait = FunctionTraitFact{
    0x5000, FunctionTraitKind::CallingConvention,
    TraitValue::text("sysv")};
  expect(normalize_payload(wrapper_trait, &error) &&
           normalize_payload(convention_trait, &error),
         "typed unsigned and text function-trait constructors validate");

  FactPayload bad_register = RegisterValueFact{
    0x6000, RegisterStatePoint::BeforeInstruction, "", {1}};
  expect(!normalize_payload(bad_register, &error),
         "register values require a stable register identifier");

  CallObservationFact conflicting_call;
  conflicting_call.source = 0x7000;
  conflicting_call.arguments = {{0, "reg:x0", {1}}, {0, "reg:x0", {2}}};
  FactPayload bad_call = conflicting_call;
  expect(!normalize_payload(bad_call, &error),
         "one call observation cannot assign one ABI carrier two values");

  CallObservationFact impossible_return;
  impossible_return.source = 0x7000;
  impossible_return.result = CallResult::NoReturn;
  impossible_return.returns = {{0, "reg:x0", {1}}};
  bad_call = impossible_return;
  expect(!normalize_payload(bad_call, &error),
         "known call return values require a returned outcome");
}

void test_decoder_robustness()
{
  const FactPayload source = DispatchMapFact{
    0x12345678,
    {{uint64_t{0}, 0x2000}, {uint64_t{7}, 0x3000}, {std::nullopt, 0x4000}},
    Address{0x5000}, true};
  std::vector<uint8_t> canonical;
  std::string error;
  expect(encode_payload(source, canonical, &error),
         "robustness fixture encodes");

  const FactPayload sentinel = CodeTargetFact{
    0xaaaa, 0xbbbb, CodeTargetKind::Call, false};
  for (size_t size = 0; size < canonical.size(); ++size)
  {
    std::vector<uint8_t> truncated(canonical.begin(),
                                   canonical.begin() + static_cast<std::ptrdiff_t>(size));
    FactPayload output = sentinel;
    expect(!decode_payload(truncated, output, &error),
           "every strict prefix of a payload is rejected");
    expect(payload_equal(output, sentinel),
           "failed payload decode leaves its output untouched");
  }

  // Exercise each input byte under sanitizers.  A mutation may happen to be a
  // different valid canonical fact; failures must nevertheless be transactional.
  for (size_t offset = 0; offset < canonical.size(); ++offset)
  {
    std::vector<uint8_t> mutated = canonical;
    mutated[offset] ^= static_cast<uint8_t>(1u << (offset % 8));
    FactPayload output = sentinel;
    if (!decode_payload(mutated, output, &error))
      expect(payload_equal(output, sentinel),
             "mutated invalid payload does not partially overwrite output");
  }

  FactCodecLimits tiny;
  tiny.max_fact_bytes = canonical.size() - 1;
  FactPayload limited = sentinel;
  expect(!decode_payload(canonical, limited, &error, tiny) &&
           payload_equal(limited, sentinel),
         "fact byte limit is enforced transactionally");
}

void test_dedup_merge_and_determinism()
{
  const FactPayload target = CodeTargetFact{0x1000, 0x5000,
                                             CodeTargetKind::Call, true};
  EvidenceStore store;
  AddResult first = store.add(observed(target, 10, 100));
  AddResult duplicate = store.add(observed(target, 10, 100));
  AddResult second_run = store.add(observed(target, 11, 101));
  AnalysisFact invalid = observed(MemoryAccessFact{0x1000, 0x2000, 0,
                                                   MemoryAccessKind::Read}, 1, 1);
  AddResult rejected = store.add(std::move(invalid));
  expect(first.disposition == AddDisposition::InsertedRecord,
         "first semantic fact creates a record");
  expect(duplicate.disposition == AddDisposition::DuplicateObservation,
         "identical observation is deduplicated");
  expect(second_run.disposition == AddDisposition::AddedObservation,
         "same semantic fact from another run retains new provenance");
  expect(rejected.disposition == AddDisposition::RejectedInvalid &&
           !rejected.error.empty(),
         "store rejects malformed producer output with a diagnostic");
  expect(store.record_count() == 1 && store.observation_count() == 2,
         "record and observation counts distinguish semantic dedup from provenance");

  const EvidenceRecord *record = store.find(target);
  expect(record != nullptr, "semantic lookup finds a normalized payload");
  if (record != nullptr)
  {
    const SupportSummary summary = summarize_support(*record);
    expect(summary.observation_count == 2 && summary.distinct_run_count == 2 &&
             summary.distinct_seed_count == 2 &&
             summary.minimum_generation == 0x100000002ULL,
           "support summary counts distinct 64-bit run/seed/generation provenance");
    expect(is_corroborated(*record, 2, 1, 9000),
           "two high-confidence explicit runs corroborate a fact");
    expect(!is_corroborated(*record, 3, 1, 0),
           "raw observation count cannot satisfy a larger run threshold");
  }

  EvidenceStore other;
  other.add(observed(target, 12, 102, "test.static"));
  other.add(observed(MemoryAccessFact{0x1010, 0x7000, 4,
                                      MemoryAccessKind::Read}, 12, 102));
  MergeReport merged = store.merge(other);
  expect(merged.inserted_records == 1 && merged.added_observations == 1 &&
           merged.records_after == 2 && merged.observations_after == 4,
         "multi-store merge reports records and observations accurately");

  const std::vector<AnalysisFact> canonical = store.flattened_facts();
  EvidenceStore reverse;
  for (auto it = canonical.rbegin(); it != canonical.rend(); ++it)
    reverse.add(*it);
  std::vector<uint8_t> forward_bytes, reverse_bytes;
  std::string error;
  expect(store.serialize(forward_bytes, &error) &&
           reverse.serialize(reverse_bytes, &error) &&
           forward_bytes == reverse_bytes,
         "serialization is independent of fact insertion order");

  EvidenceStore round_trip;
  expect(EvidenceStore::deserialize(forward_bytes, round_trip, &error),
         "canonical evidence store deserializes: " + error);
  std::vector<uint8_t> round_trip_bytes;
  expect(round_trip.serialize(round_trip_bytes, &error) &&
           round_trip_bytes == forward_bytes,
         "store serialization is byte-stable after round trip");

  StoreCodecLimits tight;
  tight.max_observations = 1;
  EvidenceStore limited;
  expect(!EvidenceStore::deserialize(forward_bytes, limited, &error, tight),
         "configured observation limit is enforced before decoding facts");

  EvidenceStore unchanged;
  unchanged.add(observed(CodeRegionFact{0x9000, 0x9010, CodeRegionKind::Code}, 1, 1));
  const size_t unchanged_count = unchanged.observation_count();
  std::vector<uint8_t> corrupt = forward_bytes;
  corrupt[20] ^= 0x80;
  expect(!EvidenceStore::deserialize(corrupt, unchanged, &error) &&
           unchanged.observation_count() == unchanged_count,
         "checksum failure is detected transactionally without changing output");

  std::vector<uint8_t> wrong_magic = forward_bytes;
  wrong_magic[0] ^= 1;
  reseal_store_blob(wrong_magic);
  expect(!EvidenceStore::deserialize(wrong_magic, unchanged, &error) &&
           unchanged.observation_count() == unchanged_count,
         "a correctly checksummed envelope with wrong magic is rejected transactionally");

  std::vector<uint8_t> wrong_version = forward_bytes;
  wrong_version[8] = 0;
  wrong_version[9] = 2;
  reseal_store_blob(wrong_version);
  expect(!EvidenceStore::deserialize(wrong_version, unchanged, &error),
         "unsupported store schema versions are rejected after integrity verification");

  // The first fact starts after the 24-byte envelope header and its 4-byte
  // length.  Corrupt its nested magic, then recompute the outer checksum to
  // prove validation does not rely on the checksum alone.
  std::vector<uint8_t> bad_nested_fact = forward_bytes;
  bad_nested_fact[28] ^= 1;
  reseal_store_blob(bad_nested_fact);
  expect(!EvidenceStore::deserialize(bad_nested_fact, unchanged, &error),
         "invalid nested fact is rejected even with a valid envelope checksum");

  std::vector<uint8_t> trailing = forward_bytes;
  trailing.insert(trailing.end() - 32, 0);
  reseal_store_blob(trailing);
  expect(!EvidenceStore::deserialize(trailing, unchanged, &error),
         "checksummed trailing envelope bytes are rejected as non-canonical");

  EvidenceStore cleared = unchanged;
  cleared.clear();
  expect(cleared.empty() && cleared.record_count() == 0 &&
           cleared.observation_count() == 0,
         "clear removes all records and observations");
}

void test_generation_lifecycle_regression()
{
  // Mirrors the native analyzer's reset path: the semantic payload remains
  // identical while a new analysis generation contributes new provenance.
  // Repeated copy/move/destruction also guards the out-of-line store ABI
  // boundary used by the IDA plugin.
  for (uint64_t cycle = 0; cycle != 40; ++cycle)
  {
    EvidenceStore store;
    const FactPayload payload = CodeTargetFact{
      0x1100, 0x5000, CodeTargetKind::Call, true};
    for (uint64_t generation = 1; generation <= 32; ++generation)
    {
      Evidence native;
      native.producer = "viy.native.ida";
      native.method = "ida.regfinder.indirect_target";
      native.proof = ProofKind::StaticProof;
      native.confidence = 9500;
      native.scope.function_start = 0x1000;
      native.scope.generation = cycle * 100 + generation;
      native.support_addresses = {0x1100, 0x10f0};
      AnalysisFact fact{payload, native};
      const AddResult added = store.add(fact);
      expect(added.disposition == (generation == 1
        ? AddDisposition::InsertedRecord : AddDisposition::AddedObservation),
        "new native generation adds provenance to one semantic record");
      expect(store.add(std::move(fact)).disposition ==
               AddDisposition::DuplicateObservation,
             "same native generation remains an exact duplicate");
    }
    expect(store.record_count() == 1 && store.observation_count() == 32,
           "native generations coalesce without losing observations");

    EvidenceStore copied(store);
    EvidenceStore moved(std::move(copied));
    EvidenceStore copy_assigned;
    copy_assigned = moved;
    EvidenceStore move_assigned;
    move_assigned = std::move(copy_assigned);
    expect(moved.observation_count() == 32 && move_assigned.observation_count() == 32,
           "store copy/move special members preserve generation evidence");
  }
}

void test_latest_generation_view()
{
  const FactPayload stale_target = CodeTargetFact{
    0x1100, 0x5000, CodeTargetKind::Jump, true};
  const FactPayload current_target = CodeTargetFact{
    0x1100, 0x6000, CodeTargetKind::Jump, true};

  auto scoped = [](FactPayload payload,
                   std::string producer,
                   Address function,
                   uint64_t generation,
                   uint64_t run,
                   std::string method = "snapshot") {
    Evidence observation = evidence(run, run, std::move(producer),
                                    std::move(method));
    observation.scope.function_start = function;
    observation.scope.function_end = function + 0x100;
    observation.scope.generation = generation;
    return AnalysisFact{std::move(payload), std::move(observation)};
  };

  EvidenceStore history;
  history.add(scoped(stale_target, "producer.a", 0x1000, 7, 1));
  history.add(scoped(current_target, "producer.a", 0x1000, 8, 2));
  // A second observation tied at the current generation must survive even
  // though its method/run provenance differs.
  history.add(scoped(current_target, "producer.a", 0x1000, 8, 3,
                     "snapshot.second_method"));

  expect(has_conflict(history.detect_conflicts(),
                      ConflictType::ConflictingUniqueCodeTarget,
                      ConflictSeverity::Contradiction),
         "full history reports a contradiction between stale and current payloads");

  std::vector<uint8_t> history_before_view;
  std::vector<uint8_t> history_after_view;
  std::string view_error;
  expect(history.serialize(history_before_view, &view_error),
         "generation-history fixture serializes before deriving a view");
  const EvidenceStore active = history.latest_generation_view();
  expect(history.serialize(history_after_view, &view_error) &&
           history_after_view == history_before_view,
         "deriving an active view does not alter persistable history bytes");
  EvidenceStore restored_history;
  expect(EvidenceStore::deserialize(history_after_view, restored_history,
                                    &view_error) &&
           restored_history.record_count() == 2 &&
           restored_history.observation_count() == 3 &&
           has_conflict(restored_history.detect_conflicts(),
                        ConflictType::ConflictingUniqueCodeTarget,
                        ConflictSeverity::Contradiction),
         "persisted history retains retired observations for audit and replay");
  expect(history.record_count() == 2 && history.observation_count() == 3,
         "constructing an active view leaves complete source history intact");
  expect(active.record_count() == 1 && active.observation_count() == 2 &&
           active.find(stale_target) == nullptr && active.find(current_target) != nullptr,
         "active view retires older payloads globally within one producer/function snapshot");
  expect(active.detect_conflicts().empty(),
         "retiring a stale generation suppresses its obsolete contradiction");
  const EvidenceRecord *current_record = active.find(current_target);
  expect(current_record != nullptr && current_record->observations.size() == 2,
         "all observations tied at the maximum generation remain active");

  // Producer generation counters are independent.  producer.b's generation 1
  // remains active even though producer.a has reached generation 8.
  history.add(scoped(stale_target, "producer.b", 0x1000, 1, 4));
  const EvidenceStore multi_producer = history.latest_generation_view();
  expect(multi_producer.record_count() == 2 &&
           multi_producer.observation_count() == 3 &&
           has_conflict(multi_producer.detect_conflicts(),
                        ConflictType::ConflictingUniqueCodeTarget,
                        ConflictSeverity::Contradiction),
         "one producer cannot retire another producer's independently current evidence");

  // A producer's other function is a separate snapshot, even when its
  // generation is numerically lower.
  const FactPayload other_function_target = CodeTargetFact{
    0x2100, 0x7000, CodeTargetKind::Jump, true};
  history.add(scoped(other_function_target, "producer.a", 0x2000, 2, 5));
  const EvidenceStore multi_function = history.latest_generation_view();
  expect(multi_function.find(other_function_target) != nullptr,
         "latest generation is selected independently for each function");

  EvidenceStore unscoped_history;
  AnalysisFact unscoped_old = scoped(stale_target, "producer.a", 0x1000, 1, 6);
  unscoped_old.evidence.scope.function_start.reset();
  unscoped_old.evidence.scope.function_end.reset();
  AnalysisFact unscoped_new = scoped(current_target, "producer.a", 0x1000, 99, 7);
  unscoped_new.evidence.scope.function_start.reset();
  unscoped_new.evidence.scope.function_end.reset();
  unscoped_history.add(std::move(unscoped_old));
  unscoped_history.add(std::move(unscoped_new));
  const EvidenceStore unscoped_active = unscoped_history.latest_generation_view();
  expect(unscoped_active.record_count() == 2 &&
           unscoped_active.observation_count() == 2 &&
           has_conflict(unscoped_active.detect_conflicts(),
                        ConflictType::ConflictingUniqueCodeTarget,
                        ConflictSeverity::Contradiction),
         "function-unscoped observations remain active at every generation");

  // Equal maximum generations retain every competing payload rather than
  // choosing one based on insertion order.
  EvidenceStore equal_generation;
  equal_generation.add(scoped(stale_target, "producer.a", 0x1000, 42, 8));
  equal_generation.add(scoped(current_target, "producer.a", 0x1000, 42, 9));
  const EvidenceStore equal_active = equal_generation.latest_generation_view();
  expect(equal_active.record_count() == 2 &&
           equal_active.observation_count() == 2 &&
           has_conflict(equal_active.detect_conflicts(),
                        ConflictType::ConflictingUniqueCodeTarget,
                        ConflictSeverity::Contradiction),
         "equal latest generations retain competing facts and their contradiction");

  const std::vector<AnalysisFact> facts = history.flattened_facts();
  EvidenceStore reverse_history;
  for (auto it = facts.rbegin(); it != facts.rend(); ++it)
    reverse_history.add(*it);
  std::vector<uint8_t> forward_bytes;
  std::vector<uint8_t> reverse_bytes;
  std::string error;
  expect(history.latest_generation_view().serialize(forward_bytes, &error) &&
           reverse_history.latest_generation_view().serialize(reverse_bytes, &error) &&
           forward_bytes == reverse_bytes,
         "active view serialization is deterministic across source insertion orders");
}

void test_conflicts()
{
  EvidenceStore store;
  uint64_t run = 1;
  auto add = [&](FactPayload payload) {
    const uint64_t current = run++;
    AnalysisFact fact = observed(std::move(payload), current, current);
    const auto *branch = std::get_if<BranchReachabilityFact>(&fact.payload);
    const auto *edge = std::get_if<CfgCandidateFact>(&fact.payload);
    if ((branch != nullptr && branch->state == Reachability::ProvenUnreachable) ||
        (edge != nullptr && edge->state == Reachability::ProvenUnreachable))
      fact.evidence.proof = ProofKind::StaticProof;
    store.add(std::move(fact));
  };

  add(CodeTargetFact{0x100, 0x1000, CodeTargetKind::Jump, true});
  add(CodeTargetFact{0x100, 0x1100, CodeTargetKind::Jump, false});

  add(BranchReachabilityFact{0x200, 0x210, Reachability::Reached});
  add(BranchReachabilityFact{0x200, 0x210, Reachability::ProvenUnreachable});
  // Non-observation must not conflict with positive evidence.
  add(BranchReachabilityFact{0x220, 0x230, Reachability::Reached});
  add(BranchReachabilityFact{0x220, 0x230, Reachability::NotObserved});

  add(MemoryValueFact{0x300, 0x3000, MemoryAccessKind::Read, {1, 2}});
  add(MemoryValueFact{0x300, 0x3000, MemoryAccessKind::Read, {1, 3}});

  add(StringCandidateFact{0x4000, StringEncoding::Ascii, {'x'}, "x", true});
  add(StringCandidateFact{0x4000, StringEncoding::Utf8, {'y'}, "y", true});

  add(FunctionCandidateFact{0x5000, Address{0x5100},
                            FunctionCandidateKind::CallTarget});
  add(FunctionCandidateFact{0x5000, Address{0x5200},
                            FunctionCandidateKind::Prologue});

  add(FunctionTraitFact{0x6000, FunctionTraitKind::Returns, TraitValue::none()});
  add(FunctionTraitFact{0x6000, FunctionTraitKind::NoReturn, TraitValue::none()});
  add(FunctionOutcomeFact{0x6000, FunctionStopKind::Returned,
                          Address{0x60ff}, int64_t{8}, uint64_t{10}});
  add(FunctionOutcomeFact{0x6000, FunctionStopKind::TimedOut,
                          Address{0x6050}, std::nullopt, uint64_t{1000}});

  add(FunctionTraitFact{0x6100, FunctionTraitKind::StackDelta,
                        TraitValue::signed_integer(8)});
  add(FunctionTraitFact{0x6100, FunctionTraitKind::StackDelta,
                        TraitValue::signed_integer(16)});

  add(CodeRegionFact{0x7000, 0x7100, CodeRegionKind::Code});
  add(CodeRegionFact{0x7080, 0x7200, CodeRegionKind::Data});

  DispatchMapFact dispatch_a;
  dispatch_a.site = 0x8000;
  dispatch_a.cases = {{uint64_t{1}, 0x8100}};
  dispatch_a.complete = true;
  DispatchMapFact dispatch_b;
  dispatch_b.site = 0x8000;
  dispatch_b.cases = {{uint64_t{1}, 0x8200}};
  add(dispatch_a);
  add(dispatch_b);

  DispatchMapFact partial_a;
  partial_a.site = 0x8300;
  partial_a.cases = {{uint64_t{1}, 0x8310}};
  DispatchMapFact partial_b = partial_a;
  partial_b.cases[0].target = 0x8320;
  add(partial_a);
  add(partial_b);

  DispatchMapFact complete_superset;
  complete_superset.site = 0x8400;
  complete_superset.cases = {{uint64_t{1}, 0x8410}, {uint64_t{2}, 0x8420}};
  complete_superset.complete = true;
  DispatchMapFact incomplete_subset;
  incomplete_subset.site = 0x8400;
  incomplete_subset.cases = {{uint64_t{1}, 0x8410}};
  add(complete_superset);
  add(incomplete_subset);

  add(CfgCandidateFact{0x9000, 0x9010, CfgEdgeKind::TrueBranch,
                       Reachability::Reached});
  add(CfgCandidateFact{0x9000, 0x9010, CfgEdgeKind::TrueBranch,
                       Reachability::ProvenUnreachable});
  add(BranchReachabilityFact{0x9100, 0x9110, Reachability::Reached});
  add(CfgCandidateFact{0x9100, 0x9110, CfgEdgeKind::TrueBranch,
                       Reachability::ProvenUnreachable});

  add(RegisterValueFact{0xa000, RegisterStatePoint::BeforeInstruction,
                        "x8", {0x01, 0x00}});
  add(RegisterValueFact{0xa000, RegisterStatePoint::BeforeInstruction,
                        "x8", {0x02, 0x00}});

  CallObservationFact call_a;
  call_a.source = 0xb000;
  call_a.target = 0xb100;
  call_a.kind = CallKind::Call;
  call_a.result = CallResult::Returned;
  call_a.arguments = {{0, "reg:x0", {1}}};
  call_a.returns = {{0, "reg:x0", {2}}};
  CallObservationFact call_b = call_a;
  call_b.target = 0xb200;
  call_b.arguments[0].bytes = {3};
  add(call_a);
  add(call_b);

  // Partial observations with identical overlap refine one another and should
  // not be reported as variation.
  CallObservationFact partial;
  partial.source = 0xb300;
  partial.target = 0xb400;
  partial.kind = CallKind::Call;
  partial.arguments = {{0, "reg:x0", {7}}};
  CallObservationFact refined = partial;
  refined.arguments.push_back({1, "reg:x1", {8}});
  add(partial);
  add(refined);

  const std::vector<EvidenceConflict> conflicts = store.detect_conflicts();
  expect(std::is_sorted(conflicts.begin(), conflicts.end(), conflict_less),
         "conflict output has deterministic canonical ordering");
  expect(has_conflict(conflicts, ConflictType::ConflictingUniqueCodeTarget,
                      ConflictSeverity::Contradiction),
         "unique code-target contradiction is detected");
  expect(has_conflict(conflicts, ConflictType::ReachableAndUnreachable,
                      ConflictSeverity::Contradiction),
         "reached/proven-unreachable contradiction is detected");
  expect(has_conflict(conflicts, ConflictType::DivergentMemoryValue,
                      ConflictSeverity::Variation),
         "dynamic memory value variation is distinguished from contradiction");
  expect(has_conflict(conflicts, ConflictType::DivergentStringCandidate,
                      ConflictSeverity::Ambiguity),
         "competing string candidates are detected as ambiguity");
  expect(has_conflict(conflicts, ConflictType::DivergentFunctionCandidate,
                      ConflictSeverity::Ambiguity),
         "function extent ambiguity is detected");
  expect(has_conflict(conflicts, ConflictType::ReturnBehaviorContradiction,
                      ConflictSeverity::Contradiction),
         "returns/no-return and concrete-return contradictions are detected");
  expect(has_conflict(conflicts, ConflictType::DivergentFunctionTrait,
                      ConflictSeverity::Variation),
         "run-dependent function trait values are detected as variation");
  expect(has_conflict(conflicts, ConflictType::DivergentFunctionOutcome,
                      ConflictSeverity::Variation),
         "run-dependent function outcomes are detected as variation");
  expect(has_conflict(conflicts, ConflictType::IncompatibleCodeRegion,
                      ConflictSeverity::Contradiction),
         "overlapping code/data regions are detected");
  expect(has_conflict(conflicts, ConflictType::DivergentDispatchCase,
                      ConflictSeverity::Contradiction),
         "complete dispatch map disagreement is detected");
  expect(has_conflict(conflicts, ConflictType::DivergentCfgReachability,
                      ConflictSeverity::Contradiction),
         "CFG reachability contradiction is detected");
  expect(has_conflict(conflicts, ConflictType::DivergentRegisterValue,
                      ConflictSeverity::Variation),
         "register-state variation across runs is detected");
  expect(has_conflict(conflicts, ConflictType::DivergentCallObservation,
                      ConflictSeverity::Variation),
         "call target and argument variation across runs is detected");

  const bool false_nonobservation_conflict =
    std::any_of(conflicts.begin(), conflicts.end(), [](const EvidenceConflict &conflict) {
      return conflict.subject == 0x220;
    });
  expect(!false_nonobservation_conflict,
         "non-observation is never promoted into an unreachable contradiction");
  const bool false_partial_call_conflict =
    std::any_of(conflicts.begin(), conflicts.end(), [](const EvidenceConflict &conflict) {
      return conflict.subject == 0xb300;
    });
  expect(!false_partial_call_conflict,
         "compatible partial call observations merge without a false conflict");
  const bool false_complete_superset_conflict =
    std::any_of(conflicts.begin(), conflicts.end(), [](const EvidenceConflict &conflict) {
      return conflict.subject == 0x8400;
    });
  expect(!false_complete_superset_conflict,
         "an incomplete subset does not contradict a compatible complete map");

  std::set<FactDigest> exhaustive_contradicted;
  for (const EvidenceConflict &conflict : conflicts)
  {
    if (conflict.severity == ConflictSeverity::Contradiction)
    {
      exhaustive_contradicted.insert(conflict.left);
      exhaustive_contradicted.insert(conflict.right);
    }
  }
  ContradictionScanStats contradiction_stats;
  const std::set<FactDigest> fast_contradicted =
    store.contradicted_payload_digests(&contradiction_stats);
  expect(fast_contradicted == exhaustive_contradicted,
         "fast contradiction scan is exactly equivalent to exhaustive conflicts");
  expect(contradiction_stats.records_indexed == store.record_count(),
         "fast contradiction scan accounts for every canonical record");
  expect(contradiction_stats.payload_digests_computed == fast_contradicted.size(),
         "fast contradiction scan hashes only participating payloads");
}

void test_persistence_adapter()
{
  EvidenceStore original;
  original.add(observed(CodeTargetFact{0x1000, 0x2000,
                                       CodeTargetKind::Call, false}, 1, 10));
  original.add(observed(CodeTargetFact{0x1000, 0x2000,
                                       CodeTargetKind::Call, false}, 2, 20));

  MemoryAdapter adapter;
  std::string error;
  expect(original.persist(adapter, &error) && !adapter.bytes.empty(),
         "persistence adapter receives the versioned store blob");

  EvidenceStore restored;
  MergeReport report;
  expect(restored.restore(adapter, RestoreMode::Replace, &report, &error) &&
           restored.record_count() == 1 && restored.observation_count() == 2 &&
           report.inserted_records == 1 && report.added_observations == 1,
         "replace restore is complete and reports imported support");

  EvidenceStore merged;
  merged.add(observed(CodeRegionFact{0x3000, 0x3010, CodeRegionKind::Code}, 4, 40));
  expect(merged.restore(adapter, RestoreMode::Merge, &report, &error) &&
           merged.record_count() == 2 && merged.observation_count() == 3,
         "merge restore preserves existing evidence");

  adapter.fail_reads = true;
  expect(!merged.restore(adapter, RestoreMode::Replace, nullptr, &error) &&
           error == "injected read failure",
         "adapter read errors propagate without clearing the store");
  adapter.fail_reads = false;
  adapter.fail_writes = true;
  expect(!original.persist(adapter, &error) && error == "injected write failure",
         "adapter write errors propagate to the caller");
}

} // namespace

int main()
{
  test_sha256();
  test_every_payload_codec();
  test_validation();
  test_decoder_robustness();
  test_dedup_merge_and_determinism();
  test_generation_lifecycle_regression();
  test_latest_generation_view();
  test_conflicts();
  test_persistence_adapter();

  if (failures != 0)
  {
    std::cerr << failures << " evidence-store test(s) failed\n";
    return 1;
  }
  std::cout << "all evidence-store tests passed\n";
  return 0;
}
