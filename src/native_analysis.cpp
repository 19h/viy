/*
 * native_analysis.cpp -- conservative, non-mutating IDA-native analysis.
 */
#include "native_analysis.hpp"
#include "evidence_store.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <allins.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <segment.hpp>
#include <xref.hpp>
#include <regfinder.hpp>

namespace viy {
namespace {

enum class FactTag : uint8_t
{
  IndirectTarget = 1,
  ZeroRegisterBranch,
  OppositeBranchPair,
  KnownFlagBranch,
  FunctionCandidate,
  DecodeDiscrepancy,
};

struct FactKey
{
  FactTag tag = FactTag::IndirectTarget;
  uint64_t a = 0;
  uint64_t b = 0;
  uint64_t c = 0;
  uint64_t d = 0;
  uint32_t x = 0;
  uint32_t y = 0;

  bool operator==(const FactKey &rhs) const
  {
    return tag == rhs.tag && a == rhs.a && b == rhs.b && c == rhs.c
        && d == rhs.d && x == rhs.x && y == rhs.y;
  }
};

struct FactKeyHash
{
  size_t operator()(const FactKey &key) const noexcept
  {
    // 64-bit mix from MurmurHash3's finalizer.  This hash is used only for the
    // in-process incremental cache; persistent identity belongs to the neutral
    // fact codec and is deliberately not std::hash based.
    auto mix = [](uint64_t v) -> uint64_t
    {
      v ^= v >> 33;
      v *= UINT64_C(0xff51afd7ed558ccd);
      v ^= v >> 33;
      v *= UINT64_C(0xc4ceb9fe1a85ec53);
      return v ^ (v >> 33);
    };

    uint64_t h = mix(static_cast<uint8_t>(key.tag));
    h ^= mix(key.a + UINT64_C(0x9e3779b97f4a7c15));
    h ^= mix(key.b + (h << 1));
    h ^= mix(key.c + (h << 1));
    h ^= mix(key.d + (h << 1));
    h ^= mix((uint64_t(key.x) << 32) | key.y);
    return static_cast<size_t>(h);
  }
};

FactKey fact_key(const NativeIndirectTargetFact &f)
{
  return { FactTag::IndirectTarget, f.instruction_ea, f.target_ea,
           f.definition_ea, f.pointer_ea,
           uint32_t(f.register_id),
           uint32_t(f.kind) | (uint32_t(f.resolution) << 8)
               | (uint32_t(f.edge_already_present) << 16)
               | (uint32_t(f.value_width) << 24) };
}

FactKey fact_key(const NativeZeroRegisterBranchFact &f)
{
  return { FactTag::ZeroRegisterBranch, f.instruction_ea, f.target_ea,
           f.fallthrough_ea, 0, uint32_t(f.register_id),
           uint32_t(f.outcome) | (uint32_t(f.value_width) << 8) };
}

FactKey fact_key(const NativeOppositeBranchPairFact &f)
{
  return { FactTag::OppositeBranchPair, f.first_ea, f.second_ea,
           f.guaranteed_target_ea, f.unreachable_fallthrough_ea,
           uint32_t(f.family),
           (uint32_t(f.first_condition) << 16) | f.second_condition };
}

FactKey fact_key(const NativeKnownFlagBranchFact &f)
{
  return { FactTag::KnownFlagBranch, f.instruction_ea, f.target_ea,
           f.fallthrough_ea, f.defining_instruction_ea,
           uint32_t(f.flag) | (uint32_t(f.value) << 8)
               | (uint32_t(f.outcome) << 16),
           f.instructions_scanned };
}

FactKey fact_key(const NativeFunctionCandidateFact &f)
{
  return { FactTag::FunctionCandidate, f.callsite_ea, f.target_ea, 0, 0,
           uint32_t(f.reason),
           uint32_t(f.decoded_size)
               | (uint32_t(f.target_is_code) << 16)
               | (uint32_t(f.target_is_function_interior) << 17) };
}

FactKey fact_key(const NativeDecodeDiscrepancyFact &f)
{
  const uint64_t sizes = (uint64_t(f.idb_item_size) << 32)
                       | (uint64_t(f.decoded_size) << 16)
                       | uint64_t(f.alternate_decoded_size);
  return { FactTag::DecodeDiscrepancy, f.address, f.related_ea, sizes, 0,
           uint32_t(f.kind), uint32_t(f.observed_byte) };
}

FactKey fact_key(const NativeFactPayload &payload)
{
  return std::visit([](const auto &fact) { return fact_key(fact); }, payload);
}

NativeArchitecture detect_architecture()
{
  switch ( PH.id )
  {
    case PLFM_386:
      return NativeArchitecture::X86;
    case PLFM_ARM:
      return inf_is_64bit() ? NativeArchitecture::Arm64
                            : NativeArchitecture::Arm32;
    default:
      return NativeArchitecture::Unsupported;
  }
}

ea_t branch_target(const insn_t &insn)
{
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    const op_t &op = insn.ops[i];
    if ( op.type == o_near || op.type == o_far )
      return op.addr;
    if ( op.type == o_void )
      break;
  }
  return BADADDR;
}

bool has_exact_code_xref(ea_t from, ea_t to)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_from(from, XREF_CODE); ok; ok = xb.next_from() )
  {
    if ( !xb.iscode )
      break;
    if ( xb.to == to )
      return true;
  }
  return false;
}

bool has_alternate_predecessor(ea_t at, ea_t linear_predecessor)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_to(at, XREF_CODE); ok; ok = xb.next_to() )
  {
    if ( !xb.iscode )
      break;
    if ( xb.from != linear_predecessor )
      return true;
  }
  return false;
}

bool mapped_loaded(ea_t ea)
{
  return ea != BADADDR && is_mapped(ea) && is_loaded(ea);
}

bool executable_address(ea_t ea, bool allow_existing_code = true)
{
  if ( !mapped_loaded(ea) )
    return false;
  const segment_t *seg = getseg(ea);
  if ( seg == nullptr )
    return false;
  if ( (seg->perm & SEGPERM_EXEC) != 0 )
    return true;
  return allow_existing_code && is_code(get_flags(ea));
}

bool aligned_control_target(NativeArchitecture arch, ea_t target)
{
  if ( arch == NativeArchitecture::Arm64 )
    return (target & 3) == 0;
  // For AArch32, IDA canonicalizes Thumb code addresses by clearing bit zero.
  if ( arch == NativeArchitecture::Arm32 )
    return (target & 1) == 0;
  return true;
}

bool usable_control_target(NativeArchitecture arch, ea_t target)
{
  return aligned_control_target(arch, target)
      && executable_address(target, true);
}

bool is_direct_control_flow(const insn_t &insn)
{
  if ( branch_target(insn) == BADADDR )
    return false;
  if ( is_call_insn(insn) )
    return true;
  return is_basic_block_end(insn, false);
}

std::string operand_register_name(const op_t &op, size_t *width_out = nullptr)
{
  if ( op.type != o_reg )
    return {};
  qstring name;
  size_t width = get_dtype_size(op.dtype);
  if ( width == 0 || width == size_t(-1) )
    width = 8;
  if ( width_out != nullptr )
    *width_out = width;
  if ( get_reg_name(&name, op.reg, width) < 0 )
    return {};
  std::string n(name.c_str());
  std::transform(n.begin(), n.end(), n.begin(),
                 [](unsigned char c) { return char(std::tolower(c)); });
  return n;
}

bool is_zero_register(const op_t &op)
{
  std::string n = operand_register_name(op);
  std::transform(n.begin(), n.end(), n.begin(),
                 [](unsigned char c) { return char(std::toupper(c)); });
  return n == "XZR" || n == "WZR";
}

enum class X86Condition : uint16_t
{
  Overflow = 0,
  NotOverflow,
  Carry,
  NotCarry,
  Zero,
  NotZero,
  BelowOrEqual,
  Above,
  Sign,
  NotSign,
  Parity,
  NotParity,
  Less,
  GreaterOrEqual,
  LessOrEqual,
  Greater,
  Invalid = 0xffff,
};

X86Condition x86_condition(uint16_t itype)
{
  switch ( itype )
  {
    case NN_jo:   return X86Condition::Overflow;
    case NN_jno:  return X86Condition::NotOverflow;
    case NN_jb:
    case NN_jc:
    case NN_jnae: return X86Condition::Carry;
    case NN_jnb:
    case NN_jnc:
    case NN_jae:  return X86Condition::NotCarry;
    case NN_jz:
    case NN_je:   return X86Condition::Zero;
    case NN_jnz:
    case NN_jne:  return X86Condition::NotZero;
    case NN_jbe:
    case NN_jna:  return X86Condition::BelowOrEqual;
    case NN_ja:
    case NN_jnbe: return X86Condition::Above;
    case NN_js:   return X86Condition::Sign;
    case NN_jns:  return X86Condition::NotSign;
    case NN_jp:
    case NN_jpe:  return X86Condition::Parity;
    case NN_jnp:
    case NN_jpo:  return X86Condition::NotParity;
    case NN_jl:
    case NN_jnge: return X86Condition::Less;
    case NN_jnl:
    case NN_jge:  return X86Condition::GreaterOrEqual;
    case NN_jle:
    case NN_jng:  return X86Condition::LessOrEqual;
    case NN_jnle:
    case NN_jg:   return X86Condition::Greater;
    default:      return X86Condition::Invalid;
  }
}

bool opposite_x86_conditions(X86Condition a, X86Condition b)
{
  if ( a == X86Condition::Invalid || b == X86Condition::Invalid )
    return false;
  return (uint16_t(a) ^ 1u) == uint16_t(b);
}

// ARM condition values are architecturally encoded in insn_t::segpref's low
// nibble by IDA's ARM module.  Values 0..13 are paired by xor-one; 14/15 are
// AL/NV and are not accepted here.  The encoding is available through the
// public instruction representation used by ordinary SDK plugin targets.
uint16_t arm_condition(const insn_t &insn)
{
  return uint16_t(insn.segpref & 0x0f);
}

bool arm_branch_family(
    const insn_t &a,
    const insn_t &b,
    NativeOppositeBranchFamily *family,
    uint16_t *first_cond,
    uint16_t *second_cond)
{
  if ( a.itype == ARM_b && b.itype == ARM_b )
  {
    const uint16_t ca = arm_condition(a);
    const uint16_t cb = arm_condition(b);
    if ( ca >= 14 || cb >= 14 || (ca ^ 1u) != cb )
      return false;
    *family = NativeOppositeBranchFamily::ArmCondition;
    *first_cond = ca;
    *second_cond = cb;
    return true;
  }

  if ( ((a.itype == ARM_cbz && b.itype == ARM_cbnz)
     || (a.itype == ARM_cbnz && b.itype == ARM_cbz))
    && a.Op1.type == o_reg && b.Op1.type == o_reg
    && a.Op1.reg == b.Op1.reg )
  {
    *family = NativeOppositeBranchFamily::ArmCompareZero;
    *first_cond = a.itype;
    *second_cond = b.itype;
    return true;
  }

  if ( ((a.itype == ARM_tbz && b.itype == ARM_tbnz)
     || (a.itype == ARM_tbnz && b.itype == ARM_tbz))
    && a.Op1.type == o_reg && b.Op1.type == o_reg
    && a.Op1.reg == b.Op1.reg
    && a.Op2.type == o_imm && b.Op2.type == o_imm
    && a.Op2.value == b.Op2.value )
  {
    *family = NativeOppositeBranchFamily::ArmTestBit;
    *first_cond = a.itype;
    *second_cond = b.itype;
    return true;
  }
  return false;
}

bool operands_equivalent(const op_t &a, const op_t &b)
{
  if ( a.type != b.type || a.dtype != b.dtype || a.flags != b.flags )
    return false;
  if ( a.type == o_void )
    return true;
  return a.reg == b.reg
      && a.value == b.value
      && a.addr == b.addr
      && a.specval == b.specval
      && a.specflag1 == b.specflag1
      && a.specflag2 == b.specflag2
      && a.specflag3 == b.specflag3
      && a.specflag4 == b.specflag4;
}

bool instructions_equivalent_ignoring_legacy_prefix(
    const insn_t &prefixed,
    const insn_t &plain)
{
  if ( prefixed.itype != plain.itype || prefixed.size != plain.size + 1 )
    return false;
  if ( prefixed.get_canon_feature(PH) != plain.get_canon_feature(PH) )
    return false;
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    if ( !operands_equivalent(prefixed.ops[i], plain.ops[i]) )
      return false;
    if ( prefixed.ops[i].type == o_void )
      break;
  }
  return true;
}

bool legacy_prefix_may_be_redundant(ea_t ea, const insn_t &prefixed)
{
  const uint8_t prefix = get_byte(ea);
  if ( prefix != 0xf2 && prefix != 0xf3 )
    return false;
  if ( !is_loaded(ea + 1) )
    return false;
  const uint8_t opcode = get_byte(ea + 1);

  // Mandatory SIMD/CET encodings, prefix trains, HLE, PAUSE, AMD REP RET,
  // string/port operations, and MPX BND control-flow prefixes are not
  // semantically redundant even if a decoder reports the same itype.
  if ( opcode == 0x0f || opcode == 0x66 || opcode == 0x67 || opcode == 0xf0
    || opcode == 0xf2 || opcode == 0xf3 )
    return false;
  if ( prefix == 0xf3 && opcode == 0x90 )
    return false;
  if ( prefix == 0xf3
    && (opcode == 0xc2 || opcode == 0xc3
     || opcode == 0xca || opcode == 0xcb) )
    return false;
  if ( (opcode >= 0xa4 && opcode <= 0xa7)
    || (opcode >= 0xaa && opcode <= 0xaf)
    || (opcode >= 0x6c && opcode <= 0x6f) )
    return false;
  if ( is_call_insn(prefixed) || is_basic_block_end(prefixed, false) )
    return false;
  return true;
}

enum class FlagEffect : uint8_t
{
  Unknown = 0,
  Preserve,
  Clear,
  Set,
  Flip,
};

bool same_register_operands(const insn_t &insn)
{
  return insn.Op1.type == o_reg && insn.Op2.type == o_reg
      && insn.Op1.reg == insn.Op2.reg;
}

bool preserves_common_x86_flags(uint16_t itype)
{
  if ( x86_condition(itype) != X86Condition::Invalid )
    return true;
  switch ( itype )
  {
    case NN_mov:
    case NN_movsx:
    case NN_movzx:
    case NN_movsxd:
    case NN_lea:
    case NN_nop:
    case NN_not:
    case NN_push:
    case NN_pop:
    case NN_pusha:
    case NN_popa:
    case NN_pushf:
    case NN_pushfd:
    case NN_pushfq:
    case NN_xchg:
    case NN_bswap:
    case NN_leave:
    case NN_jmp:
    case NN_jmpni:
    case NN_jmpfi:
    case NN_jcxz:
    case NN_jecxz:
    case NN_jrcxz:
      return true;
    default:
      return false;
  }
}

FlagEffect flag_effect(const insn_t &insn, NativeTrackedFlag flag)
{
  if ( flag == NativeTrackedFlag::Carry )
  {
    switch ( insn.itype )
    {
      case NN_stc: return FlagEffect::Set;
      case NN_clc: return FlagEffect::Clear;
      case NN_cmc: return FlagEffect::Flip;
      case NN_and:
      case NN_or:
      case NN_test:
      case NN_xor:
        return FlagEffect::Clear;
      case NN_sub:
      case NN_cmp:
        if ( same_register_operands(insn) )
          return FlagEffect::Clear;
        break;
      // INC/DEC intentionally preserve CF while changing the other arithmetic
      // flags, so they are safe only for the CF tracker.
      case NN_inc:
      case NN_dec:
        return FlagEffect::Preserve;
    }
  }
  else
  {
    switch ( insn.itype )
    {
      case NN_xor:
      case NN_sub:
      case NN_cmp:
        if ( same_register_operands(insn) )
          return FlagEffect::Set;
        break;
      case NN_and:
        if ( insn.Op2.type == o_imm && insn.Op2.value == 0 )
          return FlagEffect::Set;
        break;
      case NN_test:
        if ( (insn.Op1.type == o_imm && insn.Op1.value == 0)
          || (insn.Op2.type == o_imm && insn.Op2.value == 0) )
        {
          return FlagEffect::Set;
        }
        break;
      // Carry-only instructions do not alter ZF.
      case NN_stc:
      case NN_clc:
      case NN_cmc:
        return FlagEffect::Preserve;
    }
  }
  return preserves_common_x86_flags(insn.itype)
       ? FlagEffect::Preserve
       : FlagEffect::Unknown;
}

struct FlagScanResult
{
  bool known = false;
  NativeFlagValue value = NativeFlagValue::Clear;
  ea_t definition_ea = BADADDR;
  uint32_t scanned = 0;
};

FlagScanResult scan_known_flag(
    ea_t branch_ea,
    ea_t chunk_start,
    uint32_t depth,
    NativeTrackedFlag flag)
{
  FlagScanResult result;
  ea_t scan = branch_ea;
  bool flipped = false;
  for ( uint32_t i = 0; i < depth; ++i )
  {
    const ea_t prev = prev_head(scan, chunk_start);
    if ( prev == BADADDR || prev < chunk_start || !is_code(get_flags(prev)) )
      return result;

    insn_t insn;
    if ( decode_insn(&insn, prev) <= 0 || prev + insn.size != scan )
      return result;
    if ( has_alternate_predecessor(scan, prev) )
      return result;

    ++result.scanned;
    const FlagEffect effect = flag_effect(insn, flag);
    if ( effect == FlagEffect::Flip )
    {
      flipped = !flipped;
      scan = prev;
      continue;
    }
    if ( effect == FlagEffect::Set || effect == FlagEffect::Clear )
    {
      bool set = effect == FlagEffect::Set;
      if ( flipped )
        set = !set;
      result.known = true;
      result.value = set ? NativeFlagValue::Set : NativeFlagValue::Clear;
      result.definition_ea = prev;
      return result;
    }
    if ( effect != FlagEffect::Preserve )
      return result;
    scan = prev;
  }
  return result;
}

bool flag_branch_outcome(
    X86Condition condition,
    NativeTrackedFlag flag,
    NativeFlagValue value,
    NativeBranchOutcome *outcome)
{
  const bool set = value == NativeFlagValue::Set;
  if ( flag == NativeTrackedFlag::Carry )
  {
    switch ( condition )
    {
      case X86Condition::Carry:
        *outcome = set ? NativeBranchOutcome::AlwaysTaken
                       : NativeBranchOutcome::NeverTaken;
        return true;
      case X86Condition::NotCarry:
        *outcome = set ? NativeBranchOutcome::NeverTaken
                       : NativeBranchOutcome::AlwaysTaken;
        return true;
      case X86Condition::BelowOrEqual:
        if ( set ) { *outcome = NativeBranchOutcome::AlwaysTaken; return true; }
        return false;
      case X86Condition::Above:
        if ( set ) { *outcome = NativeBranchOutcome::NeverTaken; return true; }
        return false;
      default:
        return false;
    }
  }

  switch ( condition )
  {
    case X86Condition::Zero:
      *outcome = set ? NativeBranchOutcome::AlwaysTaken
                     : NativeBranchOutcome::NeverTaken;
      return true;
    case X86Condition::NotZero:
      *outcome = set ? NativeBranchOutcome::NeverTaken
                     : NativeBranchOutcome::AlwaysTaken;
      return true;
    case X86Condition::BelowOrEqual:
    case X86Condition::LessOrEqual:
      if ( set ) { *outcome = NativeBranchOutcome::AlwaysTaken; return true; }
      return false;
    case X86Condition::Above:
    case X86Condition::Greater:
      if ( set ) { *outcome = NativeBranchOutcome::NeverTaken; return true; }
      return false;
    default:
      return false;
  }
}

bool direct_call_target(const insn_t &insn, ea_t *target)
{
  if ( !is_call_insn(insn) )
    return false;
  const ea_t t = branch_target(insn);
  if ( t == BADADDR || t == insn.ea + insn.size )
    return false;
  *target = t;
  return true;
}

struct ScanContext
{
  ea_t function_ea = BADADDR;
  ea_t chunk_start = BADADDR;
  ea_t chunk_end = BADADDR;
};

} // anonymous namespace

namespace {

uint16_t neutral_confidence(NativeEvidenceStrength strength)
{
  switch ( strength )
  {
    case NativeEvidenceStrength::Exact:     return analysis::kMaxConfidence;
    case NativeEvidenceStrength::Strong:    return 9500;
    case NativeEvidenceStrength::Candidate: return 7500;
  }
  return 0;
}

analysis::ProofKind neutral_proof(const NativeFactProvenance &p)
{
  if ( p.source == NativeEvidenceSource::DirectControlFlow
    && p.strength == NativeEvidenceStrength::Candidate )
  {
    return analysis::ProofKind::Heuristic;
  }
  if ( p.source == NativeEvidenceSource::IdaItemDiscrepancy )
    return analysis::ProofKind::Heuristic;
  return analysis::ProofKind::StaticProof;
}

const char *native_method(const NativeFactPayload &payload)
{
  return std::visit([](const auto &f) -> const char *
  {
    using T = std::decay_t<decltype(f)>;
    if constexpr ( std::is_same_v<T, NativeIndirectTargetFact> )
      return "ida.regfinder.indirect_target";
    if constexpr ( std::is_same_v<T, NativeZeroRegisterBranchFact> )
      return "architecture.arm64.zero_register_branch";
    if constexpr ( std::is_same_v<T, NativeOppositeBranchPairFact> )
      return "cfg.opposite_condition_pair";
    if constexpr ( std::is_same_v<T, NativeKnownFlagBranchFact> )
      return "x86.local_known_flag_branch";
    if constexpr ( std::is_same_v<T, NativeFunctionCandidateFact> )
      return "cfg.orphan_call_target";
    return "ida.decoder.discrepancy";
  }, payload);
}

analysis::Evidence neutral_evidence(const NativeFact &fact)
{
  analysis::Evidence evidence;
  evidence.producer = NativeFactProvenance::producer_name;
  evidence.method = native_method(fact.payload);
  evidence.proof = neutral_proof(fact.provenance);
  evidence.confidence = neutral_confidence(fact.provenance.strength);
  evidence.scope.generation = fact.provenance.epoch;
  if ( fact.provenance.function_ea != kNativeBadAddress )
    evidence.scope.function_start = fact.provenance.function_ea;

  std::ostringstream detail;
  detail << "native schema " << NativeFactProvenance::schema_version;
  if ( fact.provenance.chunk_start != kNativeBadAddress )
  {
    detail << "; chunk=[0x" << std::hex << fact.provenance.chunk_start
           << ",0x" << fact.provenance.chunk_end << ")" << std::dec;
  }
  detail << "; deterministic="
         << (fact.provenance.deterministic ? "true" : "false");
  evidence.detail = detail.str();
  return evidence;
}

void add_support(analysis::Evidence &evidence, uint64_t ea)
{
  if ( ea != kNativeBadAddress )
    evidence.support_addresses.push_back(ea);
}

void append_detail(analysis::Evidence &evidence, const std::string &detail)
{
  if ( !detail.empty() )
  {
    if ( !evidence.detail.empty() )
      evidence.detail += "; ";
    evidence.detail += detail;
  }
}

std::vector<uint8_t> little_endian_bytes(uint64_t value, uint8_t width)
{
  if ( width == 0 || width > sizeof(value) )
    width = sizeof(value);
  std::vector<uint8_t> bytes(width);
  for ( uint8_t i = 0; i < width; ++i )
    bytes[i] = uint8_t(value >> (8u * i));
  return bytes;
}

template <class Payload>
void emit_neutral(
    NativeAnalysisFactSink &sink,
    Payload payload,
    const analysis::Evidence &evidence)
{
  analysis::AnalysisFact fact;
  fact.payload = std::move(payload);
  fact.evidence = evidence;
  std::sort(fact.evidence.support_addresses.begin(),
            fact.evidence.support_addresses.end());
  fact.evidence.support_addresses.erase(
      std::unique(fact.evidence.support_addresses.begin(),
                  fact.evidence.support_addresses.end()),
      fact.evidence.support_addresses.end());
  sink.emit_analysis_fact(fact);
}

void emit_branch_proof(
    NativeAnalysisFactSink &sink,
    uint64_t branch,
    uint64_t target,
    uint64_t fallthrough,
    NativeBranchOutcome outcome,
    const analysis::Evidence &evidence)
{
  analysis::BranchReachabilityFact target_fact;
  target_fact.branch = branch;
  target_fact.successor = target;
  target_fact.state = outcome == NativeBranchOutcome::AlwaysTaken
                    ? analysis::Reachability::Reached
                    : analysis::Reachability::ProvenUnreachable;
  emit_neutral(sink, target_fact, evidence);

  analysis::BranchReachabilityFact fallthrough_fact;
  fallthrough_fact.branch = branch;
  fallthrough_fact.successor = fallthrough;
  fallthrough_fact.state = outcome == NativeBranchOutcome::AlwaysTaken
                         ? analysis::Reachability::ProvenUnreachable
                         : analysis::Reachability::Reached;
  emit_neutral(sink, fallthrough_fact, evidence);

  analysis::CodeTargetFact live_target;
  live_target.from = branch;
  live_target.target = outcome == NativeBranchOutcome::AlwaysTaken
                     ? target : fallthrough;
  live_target.kind = outcome == NativeBranchOutcome::AlwaysTaken
                   ? analysis::CodeTargetKind::Jump
                   : analysis::CodeTargetKind::Fallthrough;
  live_target.unique = true;
  emit_neutral(sink, live_target, evidence);
}

} // anonymous namespace

NativeAnalysisFactAdapter::NativeAnalysisFactAdapter(NativeAnalysisFactSink &sink)
  : sink_(sink)
{
}

NativeAnalysisFactAdapter::~NativeAnalysisFactAdapter() = default;

void NativeAnalysisFactAdapter::emit(const NativeFact &native)
{
  analysis::Evidence evidence = neutral_evidence(native);
  std::visit([&](const auto &fact)
  {
    using T = std::decay_t<decltype(fact)>;
    if constexpr ( std::is_same_v<T, NativeIndirectTargetFact> )
    {
      add_support(evidence, fact.instruction_ea);
      add_support(evidence, fact.definition_ea);
      add_support(evidence, fact.pointer_ea);
      std::ostringstream detail;
      detail << "register=" << fact.register_id
             << "/" << fact.register_name
             << "; resolution=" << unsigned(fact.resolution)
             << "; existing_edge="
             << (fact.edge_already_present ? "true" : "false");
      append_detail(evidence, detail.str());

      analysis::CodeTargetFact out;
      out.from = fact.instruction_ea;
      out.target = fact.target_ea;
      out.kind = fact.kind == NativeControlFlowKind::Call
               ? analysis::CodeTargetKind::Call
               : analysis::CodeTargetKind::Jump;
      out.unique = true;
      emit_neutral(sink_, out, evidence);

      if ( fact.resolution == NativeIndirectResolutionKind::RegisterValue
        && !fact.register_name.empty() )
      {
        analysis::RegisterValueFact value;
        value.instruction = fact.instruction_ea;
        value.point = analysis::RegisterStatePoint::BeforeInstruction;
        value.register_id = fact.register_name;
        value.bytes = little_endian_bytes(fact.target_ea, fact.value_width);
        emit_neutral(sink_, value, evidence);
      }
      else if ( fact.resolution
                  == NativeIndirectResolutionKind::ReadOnlyMemoryValue
             && fact.pointer_ea != kNativeBadAddress )
      {
        analysis::MemoryValueFact value;
        value.instruction = fact.instruction_ea;
        value.address = fact.pointer_ea;
        value.kind = analysis::MemoryAccessKind::Read;
        value.bytes = little_endian_bytes(fact.target_ea, fact.value_width);
        emit_neutral(sink_, value, evidence);
      }

      if ( fact.kind == NativeControlFlowKind::Call )
      {
        analysis::CallObservationFact call;
        call.source = fact.instruction_ea;
        call.target = fact.target_ea;
        call.kind = analysis::CallKind::Call;
        call.result = analysis::CallResult::Unknown;
        emit_neutral(sink_, call, evidence);
      }
    }
    else if constexpr ( std::is_same_v<T, NativeZeroRegisterBranchFact> )
    {
      add_support(evidence, fact.instruction_ea);
      append_detail(evidence, "operand is the architectural zero register");
      emit_branch_proof(sink_, fact.instruction_ea, fact.target_ea,
                        fact.fallthrough_ea, fact.outcome, evidence);
      if ( !fact.register_name.empty() )
      {
        analysis::RegisterValueFact value;
        value.instruction = fact.instruction_ea;
        value.point = analysis::RegisterStatePoint::BeforeInstruction;
        value.register_id = fact.register_name;
        value.bytes.assign(fact.value_width == 0 ? 8 : fact.value_width, 0);
        emit_neutral(sink_, value, evidence);
      }
    }
    else if constexpr ( std::is_same_v<T, NativeOppositeBranchPairFact> )
    {
      add_support(evidence, fact.first_ea);
      add_support(evidence, fact.second_ea);
      std::ostringstream detail;
      detail << "family=" << unsigned(fact.family)
             << "; conditions=" << fact.first_condition
             << "/" << fact.second_condition;
      append_detail(evidence, detail.str());

      // The pair as a whole has exactly one successor.  Keep both the collapsed
      // target and the proof that falling through the second branch is invalid.
      analysis::CodeTargetFact target;
      target.from = fact.first_ea;
      target.target = fact.guaranteed_target_ea;
      target.kind = analysis::CodeTargetKind::Jump;
      target.unique = true;
      emit_neutral(sink_, target, evidence);

      analysis::BranchReachabilityFact reached;
      reached.branch = fact.first_ea;
      reached.successor = fact.guaranteed_target_ea;
      reached.state = analysis::Reachability::Reached;
      emit_neutral(sink_, reached, evidence);

      analysis::BranchReachabilityFact unreachable;
      unreachable.branch = fact.second_ea;
      unreachable.successor = fact.unreachable_fallthrough_ea;
      unreachable.state = analysis::Reachability::ProvenUnreachable;
      emit_neutral(sink_, unreachable, evidence);
    }
    else if constexpr ( std::is_same_v<T, NativeKnownFlagBranchFact> )
    {
      add_support(evidence, fact.instruction_ea);
      add_support(evidence, fact.defining_instruction_ea);
      std::ostringstream detail;
      detail << "flag="
             << (fact.flag == NativeTrackedFlag::Carry ? "CF" : "ZF")
             << "; value="
             << (fact.value == NativeFlagValue::Set ? "set" : "clear")
             << "; backward_instructions=" << fact.instructions_scanned;
      append_detail(evidence, detail.str());
      emit_branch_proof(sink_, fact.instruction_ea, fact.target_ea,
                        fact.fallthrough_ea, fact.outcome, evidence);
      analysis::RegisterValueFact value;
      value.instruction = fact.instruction_ea;
      value.point = analysis::RegisterStatePoint::BeforeInstruction;
      value.register_id = fact.flag == NativeTrackedFlag::Carry
                        ? "flags:cf" : "flags:zf";
      value.bytes = { fact.value == NativeFlagValue::Set ? uint8_t(1)
                                                        : uint8_t(0) };
      emit_neutral(sink_, value, evidence);
    }
    else if constexpr ( std::is_same_v<T, NativeFunctionCandidateFact> )
    {
      add_support(evidence, fact.callsite_ea);
      std::ostringstream detail;
      detail << "native_reason=" << unsigned(fact.reason)
             << "; decoded_size=" << fact.decoded_size
             << "; target_is_code="
             << (fact.target_is_code ? "true" : "false")
             << "; target_is_function_interior="
             << (fact.target_is_function_interior ? "true" : "false");
      append_detail(evidence, detail.str());

      analysis::FunctionCandidateFact out;
      out.entry = fact.target_ea;
      out.kind = analysis::FunctionCandidateKind::CallTarget;
      emit_neutral(sink_, out, evidence);

      analysis::CallObservationFact call;
      call.source = fact.callsite_ea;
      call.target = fact.target_ea;
      call.kind = analysis::CallKind::Call;
      call.result = analysis::CallResult::Unknown;
      emit_neutral(sink_, call, evidence);
    }
    else if constexpr ( std::is_same_v<T, NativeDecodeDiscrepancyFact> )
    {
      add_support(evidence, fact.address);
      add_support(evidence, fact.related_ea);
      std::ostringstream detail;
      detail << "native_kind=" << unsigned(fact.kind)
             << "; item_size=" << fact.idb_item_size
             << "; decoded_size=" << fact.decoded_size
             << "; alternate_size=" << fact.alternate_decoded_size
             << "; first_byte=0x" << std::hex << unsigned(fact.observed_byte);
      append_detail(evidence, detail.str());

      const uint64_t width = std::max<uint64_t>(
          1, std::max<uint16_t>(fact.idb_item_size, fact.decoded_size));
      analysis::CodeRegionFact region;
      region.start = fact.address;
      region.end = fact.address > std::numeric_limits<uint64_t>::max() - width
                 ? std::numeric_limits<uint64_t>::max()
                 : fact.address + width;
      switch ( fact.kind )
      {
        case NativeDecodeDiscrepancyKind::RedundantLegacyPrefix:
        case NativeDecodeDiscrepancyKind::DetachedLegacyPrefix:
          region.end = fact.address + 1;
          region.kind = analysis::CodeRegionKind::Padding;
          break;
        case NativeDecodeDiscrepancyKind::DirectTargetNotCode:
          region.kind = analysis::CodeRegionKind::Code;
          break;
        case NativeDecodeDiscrepancyKind::CodeItemSizeMismatch:
          region.kind = analysis::CodeRegionKind::Mixed;
          break;
        case NativeDecodeDiscrepancyKind::UndecodableCodeItem:
          region.kind = analysis::CodeRegionKind::Unknown;
          break;
      }
      emit_neutral(sink_, region, evidence);

      if ( fact.kind == NativeDecodeDiscrepancyKind::DirectTargetNotCode
        && fact.related_ea != kNativeBadAddress )
      {
        analysis::CodeTargetFact target;
        target.from = fact.related_ea;
        target.target = fact.address;
        target.kind = analysis::CodeTargetKind::Unknown;
        target.unique = false;
        emit_neutral(sink_, target, evidence);
      }
    }
  }, native.payload);
}

NativeEvidenceStoreSink::NativeEvidenceStoreSink(analysis::EvidenceStore &store)
  : store_(store)
{
}

NativeEvidenceStoreSink::~NativeEvidenceStoreSink() = default;

void NativeEvidenceStoreSink::emit_analysis_fact(
    const analysis::AnalysisFact &fact)
{
  const analysis::AddResult result = store_.add(fact);
  switch ( result.disposition )
  {
    case analysis::AddDisposition::InsertedRecord:
      ++report_.inserted_records;
      break;
    case analysis::AddDisposition::AddedObservation:
      ++report_.added_observations;
      break;
    case analysis::AddDisposition::DuplicateObservation:
      ++report_.duplicate_observations;
      break;
    case analysis::AddDisposition::RejectedInvalid:
      ++report_.rejected_facts;
      last_error_ = result.error;
      break;
  }
}

void NativeEvidenceStoreSink::reset_report()
{
  report_ = NativeEvidenceStoreReport{};
  last_error_.clear();
}

struct NativeAnalysisProvider::Impl
{
  using KeySet = std::unordered_set<FactKey, FactKeyHash>;

  explicit Impl(NativeFactSink &s) : sink(s) {}

  NativeFactSink &sink;
  uint64_t current_epoch = 1;
  NativeArchitecture arch = NativeArchitecture::Unsupported;
  std::unordered_map<uint64_t, KeySet> emitted_by_function;

  NativeFactProvenance provenance(
      const ScanContext &ctx,
      NativeEvidenceSource source,
      NativeEvidenceStrength strength,
      bool deterministic) const
  {
    NativeFactProvenance p;
    p.epoch = current_epoch;
    p.function_ea = ctx.function_ea == BADADDR
                  ? kNativeBadAddress : uint64_t(ctx.function_ea);
    p.chunk_start = ctx.chunk_start == BADADDR
                  ? kNativeBadAddress : uint64_t(ctx.chunk_start);
    p.chunk_end = ctx.chunk_end == BADADDR
                ? kNativeBadAddress : uint64_t(ctx.chunk_end);
    p.architecture = arch;
    p.source = source;
    p.strength = strength;
    p.deterministic = deterministic;
    return p;
  }

  template <class T>
  void emit(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      NativeFactProvenance p,
      T payload)
  {
    NativeFact fact{ std::move(p), NativeFactPayload(std::move(payload)) };
    const FactKey key = fact_key(fact.payload);
    const uint64_t scope = ctx.function_ea == BADADDR
                         ? kNativeBadAddress : uint64_t(ctx.function_ea);
    KeySet &keys = emitted_by_function[scope];
    if ( !keys.insert(key).second )
    {
      ++stats.facts_deduplicated;
      return;
    }

    sink.emit(fact);
    ++stats.facts_emitted;
    if constexpr ( std::is_same_v<T, NativeIndirectTargetFact> )
      ++stats.indirect_targets;
    else if constexpr ( std::is_same_v<T, NativeZeroRegisterBranchFact> )
      ++stats.zero_register_branches;
    else if constexpr ( std::is_same_v<T, NativeOppositeBranchPairFact> )
      ++stats.opposite_branch_pairs;
    else if constexpr ( std::is_same_v<T, NativeKnownFlagBranchFact> )
      ++stats.known_flag_branches;
    else if constexpr ( std::is_same_v<T, NativeFunctionCandidateFact> )
      ++stats.function_candidates;
    else if constexpr ( std::is_same_v<T, NativeDecodeDiscrepancyFact> )
      ++stats.decode_discrepancies;
  }

  void emit_function_candidate(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      ea_t callsite,
      ea_t target,
      bool indirect)
  {
    if ( !usable_control_target(arch, target) )
      return;

    const flags64_t flags = get_flags(target);
    if ( is_tail(flags) )
      return;

    func_t *owner = get_func(target);
    if ( owner != nullptr && owner->start_ea == target )
      return;

    insn_t first;
    if ( decode_insn(&first, target) <= 0 || first.size == 0 )
      return;

    NativeFunctionCandidateFact fact;
    fact.callsite_ea = callsite;
    fact.target_ea = target;
    fact.decoded_size = first.size;
    fact.target_is_code = is_code(flags);
    fact.target_is_function_interior = owner != nullptr;

    if ( owner != nullptr )
    {
      fact.reason = indirect
          ? NativeFunctionCandidateReason::IndirectCallToFunctionInterior
          : NativeFunctionCandidateReason::DirectCallToFunctionInterior;
    }
    else if ( fact.target_is_code )
    {
      fact.reason = indirect
          ? NativeFunctionCandidateReason::IndirectCallToUnownedCode
          : NativeFunctionCandidateReason::DirectCallToUnownedCode;
    }
    else
    {
      fact.reason = indirect
          ? NativeFunctionCandidateReason::IndirectCallToDecodableBytes
          : NativeFunctionCandidateReason::DirectCallToDecodableBytes;
    }

    emit(stats, ctx,
         provenance(ctx, NativeEvidenceSource::DirectControlFlow,
                    fact.target_is_code ? NativeEvidenceStrength::Strong
                                        : NativeEvidenceStrength::Candidate,
                    false),
         fact);
  }

  void inspect_indirect(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn,
      const NativeAnalysisOptions &options)
  {
    const bool call = is_call_insn(insn);
    const bool jump = is_indirect_jump_insn(insn);
    if ( (!call && !jump) || is_ret_insn(insn) )
      return;
    // A direct branch can still mention registers in unrelated operands.
    if ( branch_target(insn) != BADADDR )
      return;

    if ( options.regfinder_max_depth < 0 )
      return;

    const uint32_t feature = insn.get_canon_feature(PH);
    int reg = -1;
    const op_t *register_operand = nullptr;
    const op_t *memory_operand = nullptr;
    for ( int i = 0; i < UA_MAXOP; ++i )
    {
      const op_t &op = insn.ops[i];
      if ( op.type == o_void )
        break;
      const bool changes = (feature & (CF_CHG1 << i)) != 0;
      const bool uses = (feature & (CF_USE1 << i)) != 0;
      if ( changes && !uses )
        continue;
      if ( op.type == o_reg && reg < 0 )
      {
        reg = op.reg;
        register_operand = &op;
      }
      else if ( (op.type == o_mem || op.type == o_phrase
              || op.type == o_displ)
             && memory_operand == nullptr && (uses || i == 0) )
        memory_operand = &op;
    }

    auto record = [&](ea_t target,
                      ea_t definition,
                      ea_t pointer,
                      NativeIndirectResolutionKind resolution,
                      int register_id,
                      const std::string &register_name,
                      uint8_t value_width)
    {
      if ( !usable_control_target(arch, target) )
        return;

      const bool existing = has_exact_code_xref(insn.ea, target);
      if ( existing && !options.emit_existing_indirect_edges )
        return;

      NativeIndirectTargetFact fact;
      fact.instruction_ea = insn.ea;
      fact.target_ea = target;
      fact.definition_ea = definition;
      fact.pointer_ea = pointer;
      fact.kind = call ? NativeControlFlowKind::Call
                       : NativeControlFlowKind::Jump;
      fact.resolution = resolution;
      fact.register_id = register_id;
      fact.register_name = register_name;
      fact.value_width = value_width;
      fact.edge_already_present = existing;
      emit(stats, ctx,
           provenance(ctx, NativeEvidenceSource::IdaRegfinder,
                      NativeEvidenceStrength::Strong, true),
           fact);

      if ( call && options.find_function_candidates )
        emit_function_candidate(stats, ctx, insn.ea, target, true);
    };

    if ( reg >= 0 )
    {
      reg_value_info_t rvi;
      if ( !find_reg_value_info(
              &rvi, insn.ea, reg, options.regfinder_max_depth) )
      {
        stats.regfinder_supported = false;
      }
      else
      {
        uval_t value = BADADDR;
        if ( rvi.get_num(&value) )
        {
          size_t width = 0;
          const std::string name = operand_register_name(
              *register_operand, &width);
          record(ea_t(value), rvi.get_def_ea(), BADADDR,
                 NativeIndirectResolutionKind::RegisterValue, reg, name,
                 uint8_t(std::min<size_t>(
                     width, std::numeric_limits<uint8_t>::max())));
        }
      }
    }

    if ( memory_operand == nullptr )
      return;
    reg_finder_t *finder = PH.get_regfinder();
    if ( finder == nullptr )
    {
      stats.regfinder_supported = false;
      return;
    }

    reg_value_info_t address = finder->find_op_addr(
        *memory_operand, insn, options.regfinder_max_depth);
    uval_t pointer_value = BADADDR;
    if ( !address.get_num(&pointer_value) )
      return;
    const ea_t pointer = ea_t(pointer_value);
    const segment_t *pointer_segment = getseg(pointer);
    if ( pointer_segment == nullptr
      || (pointer_segment->perm & SEGPERM_WRITE) != 0 )
    {
      return; // a mutable slot is not a static sole-target proof
    }

    const size_t width = get_dtype_size(memory_operand->dtype);
    if ( width != 2 && width != 4 && width != 8 )
      return;
    if ( pointer > BADADDR - width )
      return;
    for ( size_t i = 0; i < width; ++i )
    {
      if ( !mapped_loaded(pointer + i) )
        return;
    }

    reg_value_info_t value;
    finder->emulate_mem_read(&value, address, int(width), false, insn);
    uval_t target_value = BADADDR;
    if ( !value.get_num(&target_value) )
      return;
    ea_t definition = value.get_def_ea();
    if ( definition == BADADDR )
      definition = pointer;
    record(ea_t(target_value), definition, pointer,
           NativeIndirectResolutionKind::ReadOnlyMemoryValue, -1, {},
           uint8_t(width));
  }

  void inspect_zero_register_branch(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn)
  {
    if ( arch != NativeArchitecture::Arm64 || !is_zero_register(insn.Op1) )
      return;

    NativeBranchOutcome outcome;
    switch ( insn.itype )
    {
      case ARM_cbz:
      case ARM_tbz:
        outcome = NativeBranchOutcome::AlwaysTaken;
        break;
      case ARM_cbnz:
      case ARM_tbnz:
        outcome = NativeBranchOutcome::NeverTaken;
        break;
      default:
        return;
    }
    const ea_t target = branch_target(insn);
    if ( !usable_control_target(arch, target) )
      return;

    NativeZeroRegisterBranchFact fact;
    fact.instruction_ea = insn.ea;
    fact.target_ea = target;
    fact.fallthrough_ea = insn.ea + insn.size;
    fact.outcome = outcome;
    fact.register_id = insn.Op1.reg;
    size_t register_width = 0;
    fact.register_name = operand_register_name(insn.Op1, &register_width);
    fact.value_width = uint8_t(std::min<size_t>(
        register_width, std::numeric_limits<uint8_t>::max()));
    emit(stats, ctx,
         provenance(ctx, NativeEvidenceSource::ArchitectureInvariant,
                    NativeEvidenceStrength::Exact, true),
         fact);
  }

  void inspect_opposite_pair(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &first)
  {
    const ea_t target = branch_target(first);
    if ( target == BADADDR || !usable_control_target(arch, target) )
      return;
    const ea_t second_ea = first.ea + first.size;
    if ( second_ea >= ctx.chunk_end || !is_code(get_flags(second_ea)) )
      return;

    insn_t second;
    if ( decode_insn(&second, second_ea) <= 0
      || branch_target(second) != target )
    {
      return;
    }
    const ea_t after = second.ea + second.size;
    if ( target == first.ea || target == second.ea || after == target )
      return; // no hidden/unreachable successor to recover
    if ( has_alternate_predecessor(second.ea, first.ea) )
      return;

    NativeOppositeBranchPairFact fact;
    fact.first_ea = first.ea;
    fact.second_ea = second.ea;
    fact.guaranteed_target_ea = target;
    fact.unreachable_fallthrough_ea = after;

    if ( arch == NativeArchitecture::X86 )
    {
      const X86Condition a = x86_condition(first.itype);
      const X86Condition b = x86_condition(second.itype);
      if ( !opposite_x86_conditions(a, b) )
        return;
      fact.family = NativeOppositeBranchFamily::X86Jcc;
      fact.first_condition = uint16_t(a);
      fact.second_condition = uint16_t(b);
    }
    else if ( arch == NativeArchitecture::Arm32
           || arch == NativeArchitecture::Arm64 )
    {
      if ( !arm_branch_family(first, second, &fact.family,
                              &fact.first_condition,
                              &fact.second_condition) )
      {
        return;
      }
    }
    else
    {
      return;
    }

    emit(stats, ctx,
         provenance(ctx, NativeEvidenceSource::StructuralIdentity,
                    NativeEvidenceStrength::Exact, true),
         fact);
  }

  void inspect_known_flag_branch(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &branch,
      uint32_t depth)
  {
    if ( arch != NativeArchitecture::X86 || depth == 0 )
      return;
    const X86Condition condition = x86_condition(branch.itype);
    const ea_t target = branch_target(branch);
    if ( condition == X86Condition::Invalid
      || !usable_control_target(arch, target) )
    {
      return;
    }

    for ( NativeTrackedFlag flag :
          { NativeTrackedFlag::Carry, NativeTrackedFlag::Zero } )
    {
      const FlagScanResult scan =
          scan_known_flag(branch.ea, ctx.chunk_start, depth, flag);
      if ( !scan.known )
        continue;
      NativeBranchOutcome outcome;
      if ( !flag_branch_outcome(condition, flag, scan.value, &outcome) )
        continue;

      NativeKnownFlagBranchFact fact;
      fact.instruction_ea = branch.ea;
      fact.target_ea = target;
      fact.fallthrough_ea = branch.ea + branch.size;
      fact.defining_instruction_ea = scan.definition_ea;
      fact.flag = flag;
      fact.value = scan.value;
      fact.outcome = outcome;
      fact.instructions_scanned = scan.scanned;
      emit(stats, ctx,
           provenance(ctx, NativeEvidenceSource::LocalFlagProof,
                      NativeEvidenceStrength::Exact, true),
           fact);
    }
  }

  void inspect_direct_function_candidate(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn)
  {
    ea_t target;
    if ( direct_call_target(insn, &target) )
      emit_function_candidate(stats, ctx, insn.ea, target, false);
  }

  void inspect_direct_target_decode(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn)
  {
    if ( !is_direct_control_flow(insn) )
      return;
    const ea_t target = branch_target(insn);
    if ( !aligned_control_target(arch, target)
      || !executable_address(target, false)
      || is_code(get_flags(target)) )
    {
      return;
    }
    insn_t decoded;
    if ( decode_insn(&decoded, target) <= 0 || decoded.size == 0 )
      return;

    NativeDecodeDiscrepancyFact fact;
    fact.address = target;
    fact.related_ea = insn.ea;
    fact.kind = NativeDecodeDiscrepancyKind::DirectTargetNotCode;
    fact.decoded_size = decoded.size;
    fact.observed_byte = get_byte(target);
    emit(stats, ctx,
         provenance(ctx, NativeEvidenceSource::DirectControlFlow,
                    NativeEvidenceStrength::Strong, false),
         fact);
  }

  void inspect_prefix(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn)
  {
    if ( arch != NativeArchitecture::X86 )
      return;

    // Prefix is part of the current code item.
    if ( legacy_prefix_may_be_redundant(insn.ea, insn) )
    {
      insn_t plain;
      if ( decode_insn(&plain, insn.ea + 1) > 0
        && instructions_equivalent_ignoring_legacy_prefix(insn, plain) )
      {
        NativeDecodeDiscrepancyFact fact;
        fact.address = insn.ea;
        fact.related_ea = insn.ea + 1;
        fact.kind = NativeDecodeDiscrepancyKind::RedundantLegacyPrefix;
        fact.idb_item_size = get_item_size(insn.ea);
        fact.decoded_size = insn.size;
        fact.alternate_decoded_size = plain.size;
        fact.observed_byte = get_byte(insn.ea);
        emit(stats, ctx,
             provenance(ctx, NativeEvidenceSource::DecoderEquivalence,
                        NativeEvidenceStrength::Strong, true),
             fact);
      }
    }

    // IDA starts code one byte after a loaded prefix.  Require that the prefix
    // is unreferenced, unnamed, not code, in the same chunk, and that decoding
    // it produces the exact same instruction plus one byte.
    if ( insn.ea <= ctx.chunk_start )
      return;
    const ea_t prefix_ea = insn.ea - 1;
    const flags64_t prefix_flags = get_flags(prefix_ea);
    if ( !is_loaded(prefix_ea) || is_code(prefix_flags)
      || has_xref(prefix_flags) || has_user_name(prefix_flags) )
    {
      return;
    }
    insn_t prefixed;
    if ( decode_insn(&prefixed, prefix_ea) <= 0
      || !legacy_prefix_may_be_redundant(prefix_ea, prefixed)
      || !instructions_equivalent_ignoring_legacy_prefix(prefixed, insn) )
    {
      return;
    }

    NativeDecodeDiscrepancyFact fact;
    fact.address = prefix_ea;
    fact.related_ea = insn.ea;
    fact.kind = NativeDecodeDiscrepancyKind::DetachedLegacyPrefix;
    fact.idb_item_size = get_item_size(insn.ea);
    fact.decoded_size = prefixed.size;
    fact.alternate_decoded_size = insn.size;
    fact.observed_byte = get_byte(prefix_ea);
    emit(stats, ctx,
         provenance(ctx, NativeEvidenceSource::DecoderEquivalence,
                    NativeEvidenceStrength::Strong, true),
         fact);
  }

  void inspect_instruction(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const insn_t &insn,
      const NativeAnalysisOptions &options)
  {
    if ( options.detect_decode_discrepancies )
    {
      const asize_t item_size = get_item_size(insn.ea);
      if ( item_size != 0 && item_size != insn.size )
      {
        NativeDecodeDiscrepancyFact fact;
        fact.address = insn.ea;
        fact.kind = NativeDecodeDiscrepancyKind::CodeItemSizeMismatch;
        fact.idb_item_size = uint16_t(std::min<asize_t>(
            item_size, std::numeric_limits<uint16_t>::max()));
        fact.decoded_size = insn.size;
        fact.observed_byte = get_byte(insn.ea);
        emit(stats, ctx,
             provenance(ctx, NativeEvidenceSource::IdaItemDiscrepancy,
                        NativeEvidenceStrength::Strong, true),
             fact);
      }
      inspect_prefix(stats, ctx, insn);
      inspect_direct_target_decode(stats, ctx, insn);
    }
    if ( options.resolve_indirect_control_flow )
      inspect_indirect(stats, ctx, insn, options);
    if ( options.detect_zero_register_branches )
      inspect_zero_register_branch(stats, ctx, insn);
    if ( options.detect_opposite_branch_pairs )
      inspect_opposite_pair(stats, ctx, insn);
    if ( options.track_known_x86_flags )
      inspect_known_flag_branch(stats, ctx, insn, options.flag_scan_depth);
    if ( options.find_function_candidates )
      inspect_direct_function_candidate(stats, ctx, insn);
  }

  void scan_chunk(
      NativeAnalysisStats &stats,
      const ScanContext &ctx,
      const NativeAnalysisOptions &options,
      size_t *function_instruction_count,
      size_t instruction_limit)
  {
    ++stats.chunks_scanned;
    ea_t ea = ctx.chunk_start;
    while ( ea != BADADDR && ea < ctx.chunk_end )
    {
      if ( instruction_limit != 0
        && *function_instruction_count >= instruction_limit )
      {
        return;
      }

      const flags64_t flags = get_flags(ea);
      if ( is_head(flags) && is_code(flags) )
      {
        ++*function_instruction_count;
        ++stats.instructions_scanned;
        insn_t insn;
        if ( decode_insn(&insn, ea) > 0 && insn.size != 0 )
        {
          inspect_instruction(stats, ctx, insn, options);
        }
        else
        {
          ++stats.decode_failures;
          if ( options.detect_decode_discrepancies )
          {
            NativeDecodeDiscrepancyFact fact;
            fact.address = ea;
            fact.kind = NativeDecodeDiscrepancyKind::UndecodableCodeItem;
            fact.idb_item_size = uint16_t(std::min<asize_t>(
                get_item_size(ea), std::numeric_limits<uint16_t>::max()));
            fact.observed_byte = is_loaded(ea) ? get_byte(ea) : 0;
            emit(stats, ctx,
                 provenance(ctx, NativeEvidenceSource::IdaItemDiscrepancy,
                            NativeEvidenceStrength::Strong, true),
                 fact);
          }
        }
      }

      const ea_t next = next_head(ea, ctx.chunk_end);
      if ( next == BADADDR || next <= ea )
        break;
      ea = next;
    }
  }

  bool scan_function(
      NativeAnalysisStats &stats,
      func_t *pfn,
      const NativeAnalysisOptions &options)
  {
    if ( pfn == nullptr || pfn->start_ea == BADADDR )
      return false;
    ++stats.functions_scanned;
    size_t instruction_count = 0;
    func_tail_iterator_t chunks(pfn);
    for ( bool ok = chunks.main(); ok; ok = chunks.next() )
    {
      const range_t &range = chunks.chunk();
      if ( range.empty() )
        continue;
      ScanContext ctx{ pfn->start_ea, range.start_ea, range.end_ea };
      scan_chunk(stats, ctx, options, &instruction_count,
                 options.max_instructions_per_function);
      if ( options.max_instructions_per_function != 0
        && instruction_count >= options.max_instructions_per_function )
      {
        break;
      }
    }
    return true;
  }

  void scan_unowned_code(
      NativeAnalysisStats &stats,
      const NativeAnalysisOptions &options)
  {
    size_t total = 0;
    const int count = get_segm_qty();
    for ( int i = 0; i < count; ++i )
    {
      const segment_t *seg = getnseg(i);
      if ( seg == nullptr || seg->end_ea <= seg->start_ea
        || (seg->perm & SEGPERM_EXEC) == 0 )
      {
        continue;
      }

      ea_t ea = seg->start_ea;
      while ( ea != BADADDR && ea < seg->end_ea )
      {
        if ( options.max_unowned_instructions != 0
          && total >= options.max_unowned_instructions )
        {
          return;
        }
        const flags64_t flags = get_flags(ea);
        if ( is_head(flags) && is_code(flags) && get_func(ea) == nullptr )
        {
          ScanContext ctx{ BADADDR, seg->start_ea, seg->end_ea };
          ++total;
          ++stats.instructions_scanned;
          insn_t insn;
          if ( decode_insn(&insn, ea) > 0 && insn.size != 0 )
            inspect_instruction(stats, ctx, insn, options);
          else
            ++stats.decode_failures;
        }
        const ea_t next = next_head(ea, seg->end_ea);
        if ( next == BADADDR || next <= ea )
          break;
        ea = next;
      }
    }
  }

  NativeAnalysisStats make_stats()
  {
    arch = detect_architecture();
    NativeAnalysisStats stats;
    stats.architecture = arch;
    stats.epoch = current_epoch;
    return stats;
  }
};

NativeAnalysisProvider::NativeAnalysisProvider(NativeFactSink &sink)
  : impl_(std::make_unique<Impl>(sink))
{
}

NativeAnalysisProvider::~NativeAnalysisProvider() = default;
NativeAnalysisProvider::NativeAnalysisProvider(NativeAnalysisProvider &&) noexcept = default;
NativeAnalysisProvider &NativeAnalysisProvider::operator=(NativeAnalysisProvider &&) noexcept = default;

NativeAnalysisStats NativeAnalysisProvider::analyze_database(
    const NativeAnalysisOptions &options)
{
  NativeAnalysisStats stats = impl_->make_stats();
  if ( impl_->arch == NativeArchitecture::Unsupported )
    return stats;

  // Snapshot entries before invoking a sink.  The sink contract forbids IDB
  // mutation, but this also makes enumeration robust against unrelated queued
  // auto-analysis activity between complete function scans.
  std::vector<ea_t> entries;
  const size_t function_count = get_func_qty();
  const size_t limit = options.max_functions == 0
                     ? function_count
                     : std::min(function_count, options.max_functions);
  entries.reserve(limit);
  for ( size_t i = 0; i < function_count && entries.size() < limit; ++i )
  {
    const func_t *pfn = getn_func(i);
    if ( pfn != nullptr )
      entries.push_back(pfn->start_ea);
  }

  for ( ea_t entry : entries )
  {
    func_t *pfn = get_func(entry);
    if ( pfn != nullptr && pfn->start_ea == entry )
      impl_->scan_function(stats, pfn, options);
  }
  if ( options.scan_unowned_executable_code )
    impl_->scan_unowned_code(stats, options);
  return stats;
}

NativeAnalysisStats NativeAnalysisProvider::analyze_function(
    uint64_t any_ea,
    const NativeAnalysisOptions &options)
{
  NativeAnalysisStats stats = impl_->make_stats();
  if ( impl_->arch == NativeArchitecture::Unsupported
    || any_ea == kNativeBadAddress )
  {
    return stats;
  }
  func_t *pfn = get_func(ea_t(any_ea));
  if ( pfn != nullptr )
    impl_->scan_function(stats, pfn, options);
  return stats;
}

void NativeAnalysisProvider::advance_epoch()
{
  if ( ++impl_->current_epoch == 0 )
    impl_->current_epoch = 1;
}

void NativeAnalysisProvider::set_epoch(uint64_t epoch)
{
  impl_->current_epoch = epoch == 0 ? 1 : epoch;
}

void NativeAnalysisProvider::invalidate_function(uint64_t any_ea)
{
  uint64_t key = any_ea;
  if ( any_ea != kNativeBadAddress )
  {
    func_t *pfn = get_func(ea_t(any_ea));
    if ( pfn != nullptr )
      key = pfn->start_ea;
  }
  impl_->emitted_by_function.erase(key);
  advance_epoch();
}

void NativeAnalysisProvider::reset()
{
  impl_->emitted_by_function.clear();
  advance_epoch();
}

uint64_t NativeAnalysisProvider::epoch() const
{
  return impl_->current_epoch;
}

} // namespace viy
