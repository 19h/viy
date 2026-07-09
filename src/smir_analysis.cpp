#include "smir_analysis.hpp"

#include <algorithm>
#include <limits>
#include <sstream>
#include <string>
#include <utility>

namespace viy {
namespace {

using namespace analysis;

constexpr size_t kMaximumInstructionBytes = 16;
constexpr size_t kMaximumEffects = 4096;
constexpr size_t kInlineEffectCapacity = 32;

bool architecture(const ProgramImage &image, int &arch, uint32_t &mode)
{
  const uint32_t endian = image.big_endian ? RAX_MODE_BIG_ENDIAN
                                           : RAX_MODE_LITTLE_ENDIAN;
  switch ( image.arch )
  {
    case ViyArch::X86_64:  arch = RAX_ARCH_X86; mode = RAX_MODE_64; return true;
    case ViyArch::ARM64:   arch = RAX_ARCH_ARM64; mode = endian; return true;
    case ViyArch::RISCV64: arch = RAX_ARCH_RISCV64; mode = endian; return true;
    case ViyArch::HEXAGON: arch = RAX_ARCH_HEXAGON; mode = endian; return true;
    // The rax 1.3 rich-effect contract deliberately excludes these modes.
    case ViyArch::X86_16:  arch = RAX_ARCH_X86; mode = RAX_MODE_16; return true;
    case ViyArch::X86_32:  arch = RAX_ARCH_X86; mode = RAX_MODE_32; return true;
    case ViyArch::ARM32:   arch = RAX_ARCH_ARM; mode = uint32_t(endian | RAX_MODE_ARM); return true;
    case ViyArch::CORTEX_M:arch = RAX_ARCH_CORTEXM; mode = uint32_t(endian | RAX_MODE_THUMB); return true;
    default: return false;
  }
}

Evidence evidence_for(const SmirInstructionAnalysis &input,
                      const FuncRange &function, const char *method,
                      uint16_t confidence, const std::string &detail)
{
  Evidence evidence;
  evidence.producer = "viy.rax.smir";
  evidence.method = method;
  evidence.proof = ProofKind::StaticProof;
  evidence.confidence = confidence;
  evidence.scope.function_start = function.start;
  uint64_t end = function.end;
  for ( const FuncChunk &chunk : function.chunks )
    end = std::max(end, chunk.end);
  evidence.scope.function_end = end;
  evidence.scope.generation = function.generation;
  evidence.support_addresses.push_back(input.instruction);
  evidence.detail = detail;
  return evidence;
}

void account(SmirAnalysisStats &stats, const AddResult &result)
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

std::string architecture_name(int arch)
{
  switch ( arch )
  {
    case RAX_ARCH_X86: return "x86";
    case RAX_ARCH_ARM64: return "arm64";
    case RAX_ARCH_ARM: return "arm";
    case RAX_ARCH_RISCV64: return "riscv64";
    case RAX_ARCH_HEXAGON: return "hexagon";
    case RAX_ARCH_CORTEXM: return "cortexm";
    default: return "unknown";
  }
}

std::string register_id(int arch, int reg)
{
  // Use the same producer-neutral names as concrete emulation evidence.  This
  // lets EvidenceStore recognize a static constant and a runtime observation
  // as corroboration of one fact instead of two facts with private IDs.
  if ( arch == RAX_ARCH_X86 )
  {
    static const char *gprs[] = {
      "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
      "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
      "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
      "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
    };
    if ( reg >= RAX_X86_GPR64(0) && reg <= RAX_X86_GPR64(31) )
      return std::string("x86:") + gprs[reg - RAX_X86_GPR64(0)];
    if ( reg == RAX_X86_REG_RIP ) return "x86:rip";
    if ( reg == RAX_X86_REG_RFLAGS ) return "x86:rflags";
  }
  else if ( arch == RAX_ARCH_ARM64 )
  {
    if ( reg >= RAX_ARM64_X(0) && reg <= RAX_ARM64_X(30) )
      return "arm64:x" + std::to_string(reg - RAX_ARM64_X(0));
    if ( reg == RAX_ARM64_REG_SP ) return "arm64:sp";
    if ( reg == RAX_ARM64_REG_PC ) return "arm64:pc";
    if ( reg == RAX_ARM64_REG_PSTATE ) return "arm64:nzcv";
    if ( reg == RAX_ARM64_REG_FPCR ) return "arm64:fpcr";
    if ( reg == RAX_ARM64_REG_FPSR ) return "arm64:fpsr";
  }
  else if ( arch == RAX_ARCH_RISCV64 )
  {
    if ( reg >= RAX_RISCV_X(0) && reg <= RAX_RISCV_X(31) )
      return "riscv:x" + std::to_string(reg - RAX_RISCV_X(0));
    if ( reg >= RAX_RISCV_F(0) && reg <= RAX_RISCV_F(31) )
      return "riscv:f" + std::to_string(reg - RAX_RISCV_F(0));
    if ( reg == RAX_RISCV_REG_PC ) return "riscv:pc";
    if ( reg == RAX_RISCV_REG_FCSR ) return "riscv:fcsr";
  }
  else if ( arch == RAX_ARCH_HEXAGON )
  {
    if ( reg >= RAX_HEX_R(0) && reg <= RAX_HEX_R(31) )
      return "hexagon:r" + std::to_string(reg - RAX_HEX_R(0));
    if ( reg == RAX_HEX_REG_PC ) return "hexagon:pc";
  }

  std::ostringstream out;
  out << "rax:" << architecture_name(arch) << ":0x" << std::hex
      << unsigned(reg);
  return out.str();
}

std::vector<uint8_t> little_endian_value(uint64_t value, uint32_t width_bits)
{
  if ( width_bits == 0 || width_bits > 64 )
    return {};
  const size_t bytes = size_t((width_bits + 7u) / 8u);
  std::vector<uint8_t> result(bytes);
  for ( size_t i = 0; i < bytes; ++i )
    result[i] = uint8_t(value >> (i * 8u));
  return result;
}

} // namespace

bool viy_analyze_instruction_effects(const RaxApi *api,
                                     const ProgramImage &image,
                                     uint64_t instruction,
                                     uint32_t mode_override,
                                     SmirInstructionAnalysis &out)
{
  SmirInstructionAnalysis candidate;
  if ( api == nullptr || api->analyze == nullptr )
    return false;
  if ( !architecture(image, candidate.arch, candidate.mode) )
    return false;
  if ( mode_override != 0 )
    candidate.mode = mode_override;
  candidate.instruction = instruction;

  const SegImage *segment = image.segment_at(instruction);
  if ( segment == nullptr || instruction >= segment->end )
    return false;
  const uint64_t available64 = std::min<uint64_t>(
      kMaximumInstructionBytes, segment->end - instruction);
  const size_t available = size_t(available64);
  std::vector<uint8_t> bytes;
  bytes.reserve(available);
  for ( size_t i = 0; i < available; ++i )
  {
    const uint64_t ea = instruction + uint64_t(i);
    if ( !segment->byte_loaded(ea) )
      break;
    bytes.push_back(segment->bytes[size_t(ea - segment->start)]);
  }
  if ( bytes.empty() )
    return false;

  // Most instructions have fewer than ten effects. Start with a bounded
  // caller-owned array and normally lift only once; if the ABI reports BOUNDS,
  // validate the negotiation metadata and retry at the exact required size.
  // This matters in decoder audit, where a JSON/SMIR lift per IDA instruction
  // is substantially more expensive than resizing a small vector.
  candidate.effects.resize(kInlineEffectCapacity);
  size_t required = 0;
  rax_analysis summary{};
  rax_status status = api->analyze(
      candidate.arch, candidate.mode, instruction, bytes.data(), bytes.size(),
      &summary, candidate.effects.data(), candidate.effects.size(), &required);
  if ( required > kMaximumEffects
    || summary.struct_size != sizeof(rax_analysis)
    || summary.abi_version != RAX_ANALYSIS_ABI_VERSION
    || size_t(summary.required_effect_count) != required )
    return false;

  if ( status == RAX_ERR_BOUNDS )
  {
    if ( required <= candidate.effects.size()
      || size_t(summary.effect_count) != candidate.effects.size()
      || (summary.flags & RAX_ANALYSIS_TRUNCATED) == 0 )
      return false;
    candidate.effects.resize(required);
    size_t retry_required = 0;
    status = api->analyze(candidate.arch, candidate.mode, instruction,
                          bytes.data(), bytes.size(), &summary,
                          candidate.effects.data(), candidate.effects.size(),
                          &retry_required);
    if ( retry_required != required
      || summary.struct_size != sizeof(rax_analysis)
      || summary.abi_version != RAX_ANALYSIS_ABI_VERSION
      || size_t(summary.required_effect_count) != required )
      return false;
  }
  if ( status != RAX_OK || required > candidate.effects.size()
    || size_t(summary.effect_count) != required
    || (summary.flags & RAX_ANALYSIS_TRUNCATED) != 0 )
    return false;
  candidate.effects.resize(required);
  for ( const rax_analysis_effect &effect : candidate.effects )
  {
    if ( effect.struct_size != sizeof(rax_analysis_effect)
      || effect.abi_version != RAX_ANALYSIS_ABI_VERSION )
      return false;
  }
  candidate.summary = summary;
  out = std::move(candidate);
  return true;
}

SmirAnalysisStats viy_record_smir_analysis(const SmirInstructionAnalysis &input,
                                           const FuncRange &function,
                                           EvidenceStore &store)
{
  SmirAnalysisStats stats;
  ++stats.instructions_analyzed;
  if ( (input.summary.flags & RAX_ANALYSIS_UNSUPPORTED) != 0 )
    ++stats.unsupported;
  if ( (input.summary.flags & RAX_ANALYSIS_PARTIAL) != 0 )
    ++stats.partial;
  const bool complete = (input.summary.flags & RAX_ANALYSIS_COMPLETE) != 0;
  const uint16_t confidence = complete ? uint16_t(9900) : uint16_t(8500);

  const rax_decoded &decoded = input.summary.decoded;
  if ( decoded.valid != 0 && decoded.has_target != 0 )
  {
    CodeTargetKind kind = CodeTargetKind::Unknown;
    if ( decoded.flow == RAX_FLOW_CALL )
      kind = CodeTargetKind::Call;
    else if ( decoded.flow == RAX_FLOW_BRANCH
           || decoded.flow == RAX_FLOW_COND_BRANCH )
      kind = CodeTargetKind::Jump;
    if ( kind != CodeTargetKind::Unknown )
    {
      AnalysisFact fact;
      fact.payload = CodeTargetFact{ input.instruction, decoded.target, kind, true };
      fact.evidence = evidence_for(input, function, "encoded-control-target",
                                   confidence,
                                   "direct target from stateless SMIR decode");
      fact.evidence.support_addresses.push_back(decoded.target);
      account(stats, store.add(std::move(fact)));
      ++stats.code_target_facts;
    }
  }

  for ( const rax_analysis_effect &effect : input.effects )
  {
    if ( effect.kind == RAX_EFFECT_REGISTER
      && (effect.access & RAX_EFFECT_WRITE) != 0
      && effect.value_kind == RAX_VALUE_CONSTANT
      && (effect.access & RAX_EFFECT_VALUE_COMPLETE) != 0
      && effect.reg >= 0 && effect.width_bits != 0 && effect.width_bits <= 64 )
    {
      RegisterValueFact value;
      value.instruction = input.instruction;
      value.point = RegisterStatePoint::AfterInstruction;
      value.register_id = register_id(input.arch, effect.reg);
      value.bytes = little_endian_value(effect.value, effect.width_bits);
      if ( !value.bytes.empty() )
      {
        AnalysisFact fact;
        fact.payload = std::move(value);
        fact.evidence = evidence_for(input, function, "constant-register-result",
                                     confidence,
                                     "SMIR proved a direct constant result");
        account(stats, store.add(std::move(fact)));
        ++stats.register_constant_facts;
      }
    }

    if ( effect.kind == RAX_EFFECT_MEMORY
      && (effect.access & RAX_EFFECT_ADDRESS_COMPLETE) != 0
      && (effect.address_kind == RAX_ADDRESS_ABSOLUTE
       || effect.address_kind == RAX_ADDRESS_PC_RELATIVE)
      && effect.width_bits != 0 )
    {
      const uint64_t byte_count64 = (uint64_t(effect.width_bits) + 7u) / 8u;
      if ( byte_count64 == 0 || byte_count64 > std::numeric_limits<uint32_t>::max() )
        continue;
      MemoryAccessKind kind;
      const uint32_t rw = effect.access & (RAX_EFFECT_READ | RAX_EFFECT_WRITE);
      if ( rw == (RAX_EFFECT_READ | RAX_EFFECT_WRITE) )
        kind = MemoryAccessKind::ReadWrite;
      else if ( rw == RAX_EFFECT_WRITE )
        kind = MemoryAccessKind::Write;
      else if ( rw == RAX_EFFECT_READ )
        kind = MemoryAccessKind::Read;
      else
        continue;
      AnalysisFact fact;
      fact.payload = MemoryAccessFact{ input.instruction, effect.address,
                                       uint32_t(byte_count64), kind };
      fact.evidence = evidence_for(input, function, "resolved-memory-access",
                                   confidence,
                                   "SMIR resolved the effective address statically");
      fact.evidence.support_addresses.push_back(effect.address);
      account(stats, store.add(std::move(fact)));
      ++stats.memory_access_facts;
    }
  }
  return stats;
}

} // namespace viy
