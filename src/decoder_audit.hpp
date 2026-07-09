/* Cross-decoder audit: compare IDA's instruction model with rax without
 * mutating the IDB.  Every finding is emitted into the neutral evidence store. */
#pragma once

#include <cstddef>

#include "evidence_store.hpp"
#include "program_model.hpp"
#include "rax_loader.hpp"
#include "smir_analysis.hpp"

namespace viy {

struct DecoderAuditStats
{
  size_t instructions_compared = 0;
  size_t rax_decode_failures = 0;
  size_t size_disagreements = 0;
  size_t flow_disagreements = 0;
  size_t target_disagreements = 0;
  size_t target_facts = 0;
  size_t region_facts = 0;
  size_t observations_inserted = 0;
  size_t observations_deduplicated = 0;
  size_t observations_rejected = 0;
  SmirAnalysisStats smir;

  void merge_from(const DecoderAuditStats &other);
};

// Main-thread only: IDA is queried for item boundaries, decoder results,
// segment-register state and direct operands.  rax_decode is stateless.
DecoderAuditStats viy_audit_decoders(const RaxApi *api,
                                     const ProgramImage &image,
                                     const FuncRange &function,
                                     analysis::EvidenceStore &store);

} // namespace viy
