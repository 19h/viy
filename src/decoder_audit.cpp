#include "decoder_audit.hpp"

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

#include <pro.h>
#include <idp.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <segregs.hpp>

#include "decoder_core.hpp"

namespace viy {
namespace {

using namespace analysis;

DecoderArmState arm_state_at(const DecoderArchitecture &architecture,
                             ea_t ea, int thumb_reg)
{
  if ( !architecture.per_instruction_thumb || thumb_reg < 0 )
    return DecoderArmState::Unknown;
  const sel_t state = get_sreg(ea, thumb_reg);
  if ( state == BADSEL )
    return DecoderArmState::Unknown;
  return state == 0 ? DecoderArmState::Arm : DecoderArmState::Thumb;
}

ea_t ida_direct_target(const insn_t &instruction)
{
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    const op_t &operand = instruction.ops[i];
    if ( operand.type == o_near || operand.type == o_far )
      return operand.addr;
    if ( operand.type == o_void )
      break;
  }
  return BADADDR;
}

int ida_flow(const insn_t &instruction)
{
  if ( is_ret_insn(instruction) )
    return RAX_FLOW_RETURN;
  if ( is_call_insn(instruction) )
    return ida_direct_target(instruction) == BADADDR
         ? RAX_FLOW_INDIRECT_CALL : RAX_FLOW_CALL;
  const uint32_t features = instruction.get_canon_feature(PH);
  const bool transfer = (features & (CF_JUMP | CF_STOP)) != 0;
  if ( !transfer )
    return RAX_FLOW_FALLTHROUGH;
  const bool indirect = ida_direct_target(instruction) == BADADDR;
  if ( indirect )
    return RAX_FLOW_INDIRECT_JUMP;
  return (features & CF_STOP) != 0 ? RAX_FLOW_BRANCH
                                  : RAX_FLOW_COND_BRANCH;
}

DecoderInstruction ida_instruction_model(const insn_t &instruction)
{
  DecoderInstruction result;
  result.valid = instruction.size != 0;
  result.size = instruction.size;
  result.flow = ida_flow(instruction);
  result.indirect = result.flow == RAX_FLOW_INDIRECT_CALL
                 || result.flow == RAX_FLOW_INDIRECT_JUMP;
  const ea_t target = ida_direct_target(instruction);
  result.has_target = target != BADADDR;
  result.target = result.has_target ? uint64_t(target) : 0;
  return result;
}

Evidence evidence_for(const FuncRange &function, const char *producer,
                      const char *method, ProofKind proof, uint16_t confidence,
                      ea_t instruction, const std::string &detail)
{
  Evidence evidence;
  evidence.producer = producer;
  evidence.method = method;
  evidence.proof = proof;
  evidence.confidence = confidence;
  evidence.scope.function_start = function.start;
  uint64_t end = function.end;
  for ( const FuncChunk &chunk : function.chunks )
    end = std::max(end, chunk.end);
  evidence.scope.function_end = end;
  evidence.scope.generation = function.generation;
  evidence.support_addresses.push_back(uint64_t(instruction));
  evidence.detail = detail;
  return evidence;
}

void account(DecoderAuditStats &stats, const AddResult &result)
{
  switch ( result.disposition )
  {
    case AddDisposition::InsertedRecord:
    case AddDisposition::AddedObservation:
      ++stats.observations_inserted;
      break;
    case AddDisposition::DuplicateObservation:
      ++stats.observations_deduplicated;
      break;
    case AddDisposition::RejectedInvalid:
      ++stats.observations_rejected;
      break;
  }
}

void emit_region(EvidenceStore &store, DecoderAuditStats &stats,
                 const FuncRange &function, ea_t ea, uint64_t width,
                 CodeRegionKind kind, uint16_t confidence,
                 const std::string &detail)
{
  if ( width == 0 )
    width = 1;
  const uint64_t start = uint64_t(ea);
  const uint64_t end = width > std::numeric_limits<uint64_t>::max() - start
                     ? std::numeric_limits<uint64_t>::max() : start + width;
  if ( end <= start )
    return;
  AnalysisFact fact;
  fact.payload = CodeRegionFact{ start, end, kind };
  fact.evidence = evidence_for(function, "viy.decoder.audit",
                               "ida-rax-decode-disagreement",
                               ProofKind::Heuristic, confidence, ea, detail);
  account(stats, store.add(std::move(fact)));
  ++stats.region_facts;
}

void emit_target(EvidenceStore &store, DecoderAuditStats &stats,
                 const FuncRange &function, ea_t from, uint64_t target,
                 CodeTargetKind kind, const char *producer, const char *method,
                 ProofKind proof, uint16_t confidence,
                 const std::string &detail)
{
  AnalysisFact fact;
  fact.payload = CodeTargetFact{ uint64_t(from), target, kind, true };
  fact.evidence = evidence_for(function, producer, method, proof, confidence,
                               from, detail);
  fact.evidence.support_addresses.push_back(target);
  account(stats, store.add(std::move(fact)));
  ++stats.target_facts;
}

} // namespace

void DecoderAuditStats::merge_from(const DecoderAuditStats &other)
{
#define VIY_MERGE_AUDIT(field) field += other.field
  VIY_MERGE_AUDIT(instructions_compared);
  VIY_MERGE_AUDIT(rax_decode_failures);
  VIY_MERGE_AUDIT(size_disagreements);
  VIY_MERGE_AUDIT(flow_disagreements);
  VIY_MERGE_AUDIT(target_disagreements);
  VIY_MERGE_AUDIT(target_facts);
  VIY_MERGE_AUDIT(region_facts);
  VIY_MERGE_AUDIT(observations_inserted);
  VIY_MERGE_AUDIT(observations_deduplicated);
  VIY_MERGE_AUDIT(observations_rejected);
#undef VIY_MERGE_AUDIT
#define VIY_MERGE_SMIR(field) smir.field += other.smir.field
  VIY_MERGE_SMIR(instructions_analyzed);
  VIY_MERGE_SMIR(unsupported);
  VIY_MERGE_SMIR(partial);
  VIY_MERGE_SMIR(register_constant_facts);
  VIY_MERGE_SMIR(memory_access_facts);
  VIY_MERGE_SMIR(code_target_facts);
  VIY_MERGE_SMIR(observations_inserted);
  VIY_MERGE_SMIR(observations_deduplicated);
  VIY_MERGE_SMIR(observations_rejected);
#undef VIY_MERGE_SMIR
}

DecoderAuditStats viy_audit_decoders(const RaxApi *api,
                                     const ProgramImage &image,
                                     const FuncRange &function,
                                     analysis::EvidenceStore &store)
{
  DecoderAuditStats stats;
  if ( api == nullptr || (api->decode == nullptr && api->analyze == nullptr) )
    return stats;
  const DecoderArchitecture arch =
      viy_decoder_architecture(image.arch, image.big_endian);
  if ( !arch.valid )
    return stats;
  const int thumb_reg = arch.per_instruction_thumb ? str2reg("T") : -1;

  std::vector<FuncChunk> chunks = function.chunks;
  if ( chunks.empty() && function.end > function.start )
    chunks.push_back(FuncChunk{ function.start, function.end });
  constexpr size_t kMaximumBytes = 16;
  constexpr size_t kMaximumInstructions = 65536;
  size_t budget = kMaximumInstructions;
  for ( const FuncChunk &chunk : chunks )
  {
    ea_t ea = ea_t(chunk.start);
    const ea_t end = ea_t(chunk.end);
    while ( ea != BADADDR && ea < end && budget != 0 )
    {
      --budget;
      const flags64_t flags = get_flags(ea);
      if ( is_code(flags) && is_head(flags) )
      {
        insn_t ida_instruction;
        if ( decode_insn(&ida_instruction, ea) > 0 && ida_instruction.size != 0 )
        {
          ++stats.instructions_compared;
          const size_t wanted = viy_decoder_window_size(
              uint64_t(ea), uint64_t(end), kMaximumBytes);
          uint8_t bytes[kMaximumBytes] = {};
          const ssize_t got = wanted == 0 ? 0
              : get_bytes(bytes, ssize_t(wanted), ea, GMB_READALL);
          const size_t offered = got > 0 ? size_t(got) : 0;
          uint32_t mode = 0;
          const bool mode_known = viy_decoder_mode(
              arch, arm_state_at(arch, ea, thumb_reg), mode);
          DecoderDecodeResult rax_result;
          rax_result.status = DecoderDecodeStatus::InvalidInput;
          bool analyzer_returned = false;
          if ( offered != 0 && mode_known )
          {
            SmirInstructionAnalysis effects;
            if ( viy_analyze_instruction_effects(
                    api, image, uint64_t(ea), mode, effects) )
            {
              analyzer_returned = true;
              rax_result = viy_accept_rax_decoded(
                  effects.summary.decoded, offered);
              SmirAnalysisStats recorded;
              if ( rax_result.status == DecoderDecodeStatus::Valid )
                recorded = viy_record_smir_analysis(effects, function, store);
#define VIY_ADD_SMIR(field) stats.smir.field += recorded.field
              VIY_ADD_SMIR(instructions_analyzed);
              VIY_ADD_SMIR(unsupported);
              VIY_ADD_SMIR(partial);
              VIY_ADD_SMIR(register_constant_facts);
              VIY_ADD_SMIR(memory_access_facts);
              VIY_ADD_SMIR(code_target_facts);
              VIY_ADD_SMIR(observations_inserted);
              VIY_ADD_SMIR(observations_deduplicated);
              VIY_ADD_SMIR(observations_rejected);
#undef VIY_ADD_SMIR
            }
          }
          // rax_analyze already embeds the identical decoded-flow summary. Do
          // not lift the instruction again merely to call rax_decode; retain a
          // 1.2 fallback when the richer optional capability is absent. If an
          // analyzer result itself is malformed, reject it consistently rather
          // than masking a cross-capability ABI disagreement with another call.
          if ( !analyzer_returned && offered != 0 && mode_known )
            rax_result = viy_decode_one(api->decode, arch.rax_arch, mode,
                                        uint64_t(ea), bytes, offered);
          if ( rax_result.status != DecoderDecodeStatus::Valid )
          {
            ++stats.rax_decode_failures;
            emit_region(store, stats, function, ea, ida_instruction.size,
                        CodeRegionKind::Unknown, 6000,
                        "IDA decoded a code item but rax rejected the same bytes");
          }
          else
          {
            const DecoderInstruction ida_model =
                ida_instruction_model(ida_instruction);
            const DecoderInstruction &rax_model = rax_result.instruction;
            const DecoderComparison comparison =
                viy_compare_decoders(ida_model, rax_model);
            if ( comparison.size_disagreement )
            {
              ++stats.size_disagreements;
              std::ostringstream detail;
              detail << "IDA size=" << unsigned(ida_instruction.size)
                     << "; rax size=" << rax_model.size;
              emit_region(store, stats, function, ea,
                          std::max<uint64_t>(rax_model.size, ida_instruction.size),
                          CodeRegionKind::Mixed, 8500, detail.str());
            }

            if ( comparison.flow_disagreement )
            {
              ++stats.flow_disagreements;
              std::string detail = std::string("IDA flow=")
                                 + viy_decoder_flow_name(ida_model.flow)
                                 + "; rax flow="
                                 + viy_decoder_flow_name(rax_model.flow);
              emit_region(store, stats, function, ea,
                          std::max<uint64_t>(rax_model.size, ida_instruction.size),
                          CodeRegionKind::Mixed, 8000, detail);
            }

            if ( comparison.right_target.valid )
            {
              const CodeTargetKind target_kind =
                  comparison.right_target.kind == DecoderTargetKind::Call
                ? CodeTargetKind::Call : CodeTargetKind::Jump;
              emit_target(store, stats, function, ea,
                          comparison.right_target.address, target_kind,
                          "viy.rax.decoder", "direct-control-target",
                          ProofKind::StaticProof, 9800,
                          "direct target encoded in the instruction");
            }

            if ( comparison.left_target.valid )
            {
              const CodeTargetKind ida_kind =
                  comparison.left_target.kind == DecoderTargetKind::Call
                ? CodeTargetKind::Call : CodeTargetKind::Jump;
              emit_target(store, stats, function, ea,
                          comparison.left_target.address, ida_kind,
                          "ida.decoder", "direct-control-target",
                          ProofKind::Imported, 9500,
                          "direct target reported by IDA's processor module");
            }
            if ( comparison.target_disagreement )
              ++stats.target_disagreements;
          }
        }
      }
      const ea_t next = next_head(ea, end);
      if ( next == BADADDR || next <= ea )
        break;
      ea = next;
    }
    if ( budget == 0 )
      break;
  }
  return stats;
}

} // namespace viy
