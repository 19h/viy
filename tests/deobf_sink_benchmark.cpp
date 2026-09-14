// Standalone before/after benchmark; link against either revision's sink/store.
#include "deobf_analysis.hpp"
#include "evidence_store.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>

int main()
{
  using namespace viy;
  using namespace viy::analysis;
  for (const bool edges : {false, true})
    for (const size_t count : {size_t{1000}, size_t{2000}, size_t{4000}})
    {
      EvidenceStore store;
      DeobfEvidenceStoreSink sink(store);
      sink.set_active_generation(1);
      Evidence observation;
      observation.producer = "benchmark";
      observation.method = "static";
      observation.proof = ProofKind::StaticProof;
      observation.scope.generation = 1;
      observation.confidence = 9000;
      const auto start = std::chrono::steady_clock::now();
      for (size_t i = 0; i < count; ++i)
      {
        FactPayload payload;
        if (edges)
          payload = BranchReachabilityFact{0x1000 + i * 16, 0x1008 + i * 16,
                                           Reachability::Reached};
        else
          payload = FunctionTraitFact{0x1000 + i * 16, FunctionTraitKind::ReturnConstant,
                                      TraitValue::unsigned_integer(i)};
        if (!sink.emit_deobf_fact({payload, observation}))
          return 1;
      }
      const double elapsed = std::chrono::duration<double>(
          std::chrono::steady_clock::now() - start).count();
      if (store.record_count() != count || sink.report().inserted_records != count)
        return 1;
      std::cout << (edges ? "edges" : "traits") << ',' << count << ',' << elapsed
                << '\n' << std::flush;
    }
}
