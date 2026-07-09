#include "evidence_lifecycle.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

using namespace viy::analysis;

namespace {

#define CHECK(expr) do { if ( !(expr) ) { \
  std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
            << ": " #expr "\n"; std::abort(); } } while ( false )

AnalysisFact target(const char *producer, uint64_t generation,
                    uint64_t function, uint64_t destination,
                    ProofKind proof = ProofKind::StaticProof)
{
  AnalysisFact fact;
  fact.payload = CodeTargetFact{ function + 4, destination,
                                 CodeTargetKind::Jump, true };
  fact.evidence.producer = producer;
  fact.evidence.method = "lifecycle-test";
  fact.evidence.proof = proof;
  fact.evidence.confidence = 9500;
  fact.evidence.scope.function_start = function;
  fact.evidence.scope.function_end = function + 0x40;
  fact.evidence.scope.generation = generation;
  fact.evidence.support_addresses = { function + 4, destination };
  return fact;
}

AnalysisFact unscoped(const char *producer, uint64_t generation,
                      uint64_t destination)
{
  AnalysisFact fact = target(producer, generation, 0x1000, destination);
  fact.evidence.scope.function_start.reset();
  fact.evidence.scope.function_end.reset();
  return fact;
}

bool has_destination(const EvidenceStore &store, uint64_t destination)
{
  for ( const EvidenceRecord &record : store.records() )
    if ( const auto *value = std::get_if<CodeTargetFact>(&record.payload) )
      if ( value->target == destination )
        return true;
  return false;
}

void test_allocator_avoids_restored_and_wraps()
{
  EvidenceStore history;
  CHECK(history.add(target("old", 1, 0x1000, 0x2000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("old", std::numeric_limits<uint64_t>::max(),
                           0x1100, 0x2100)).disposition
        == AddDisposition::InsertedRecord);

  EvidenceGenerationAllocator allocator;
  allocator.seed(history);
  const uint64_t first = allocator.allocate();
  const uint64_t second = allocator.allocate();
  CHECK(first != 0 && first != 1
        && first != std::numeric_limits<uint64_t>::max());
  CHECK(second != first && second != 1
        && second != std::numeric_limits<uint64_t>::max());
  CHECK(allocator.used().count(first) == 1);
  CHECK(allocator.used().count(second) == 1);
}

void test_exact_active_policy()
{
  EvidenceStore history;
  CHECK(history.add(target("viy.rax.emulator", 4, 0x1000, 0x2000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("viy.rax.emulator", 9, 0x1000, 0x3000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("viy.rax.emulator", 9, 0x1100, 0x3100)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("viy.native.ida", 7, 0x1000, 0x4000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("viy.native.ida", 8, 0x1000, 0x5000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(unscoped("viy.native.ida", 7, 0x4100)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(unscoped("viy.native.ida", 8, 0x5100)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(unscoped("unknown.persisted", 9, 0x6000)).disposition
        == AddDisposition::InsertedRecord);
  CHECK(history.add(target("user", 1, 0x1200, 0x7000,
                           ProofKind::UserAsserted)).disposition
        == AddDisposition::InsertedRecord);

  std::vector<uint8_t> before;
  std::string error;
  CHECK(history.serialize(before, &error));

  ActiveEvidencePolicy policy;
  policy.provider_generation = 8;
  policy.provider_functions = { 0x1000 };
  policy.function_generations = { { 0x1000, 9 } };
  const EvidenceStore active = policy.view(history);

  CHECK(!has_destination(active, 0x2000));
  CHECK(has_destination(active, 0x3000));
  CHECK(!has_destination(active, 0x3100)); // removed/out-of-scope function
  CHECK(!has_destination(active, 0x4000));
  CHECK(has_destination(active, 0x5000));
  CHECK(!has_destination(active, 0x4100));
  CHECK(has_destination(active, 0x5100));
  CHECK(!has_destination(active, 0x6000));
  CHECK(has_destination(active, 0x7000));

  std::vector<uint8_t> after;
  CHECK(history.serialize(after, &error));
  CHECK(before == after); // deriving authority never rewrites provenance
}

void test_disappeared_fact_is_retired_without_tombstone()
{
  EvidenceStore history;
  CHECK(history.add(target("viy.native.ida", 12, 0x1000, 0x2000)).disposition
        == AddDisposition::InsertedRecord);
  ActiveEvidencePolicy policy;
  policy.provider_generation = 13; // complete rescan emitted no replacement
  policy.provider_functions = { 0x1000 };
  CHECK(policy.view(history).empty());

  CHECK(history.add(target("viy.rax.emulator", 20, 0x1000, 0x3000)).disposition
        == AddDisposition::InsertedRecord);
  policy.function_generations = { { 0x1000, 21 } }; // completed new job, no fact
  CHECK(policy.view(history).empty());
}

} // namespace

int main()
{
  test_allocator_avoids_restored_and_wraps();
  test_exact_active_policy();
  test_disappeared_fact_is_retired_without_tombstone();
  return 0;
}
