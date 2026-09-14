/* Cross-decoder audit: compare IDA's instruction model with rax without
 * mutating the IDB.  Every finding is emitted into the neutral evidence store. */
#pragma once

#include <cstddef>

#include "evidence_store.hpp"
#include "program_model.hpp"
#include "rax_loader.hpp"
#include "smir_analysis.hpp"
#include "decoder_core.hpp"

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

// Immutable IDA projection captured before submission. No SDK types cross the
// worker boundary; bytes are read from the generation's shared ProgramImage.
struct DecoderAuditInput
{
  uint64_t address = 0;
  size_t maximum_bytes = 0;
  uint32_t mode = 0;
  bool mode_known = false;
  bool control_transfer = false;
  DecoderInstruction ida;
};

struct DecoderAuditInstruction
{
  DecoderAuditInput input;
  DecoderDecodeResult decoded;
  bool analyzed = false;
  SmirInstructionAnalysis effects;
};

// Main-thread SDK snapshot only. Does not call RAX or write evidence.
std::vector<DecoderAuditInput> viy_snapshot_decoder_audit(
    const ProgramImage &image, const FuncRange &function);

// Main-thread revalidation after asynchronous execution: discard inputs whose
// bytes, instruction boundaries, or ARM/Thumb mode changed during the job.
void viy_discard_stale_decoder_audit(
    const ProgramImage &image, std::vector<DecoderAuditInstruction> &instructions);

// IDA-free, stateless worker operation. Preserves the optional analyze/decode
// fallback and rejects malformed analyze output without silently decoding again.
DecoderAuditInstruction viy_analyze_decoder_input(
    const RaxApi *api, const ProgramImage &image, const DecoderAuditInput &input);

// Merge completed worker analysis into the main-thread-owned evidence store.
// Neither this function nor the snapshot routine invokes RAX.
DecoderAuditStats viy_record_decoder_audit(
    const FuncRange &function,
    const std::vector<DecoderAuditInstruction> &instructions,
    analysis::EvidenceStore &store);

} // namespace viy
