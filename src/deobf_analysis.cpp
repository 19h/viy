/*
 * deobf_analysis.cpp -- conservative IDA adapter for the IDA-free classifiers.
 */
#include "deobf_analysis.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <pro.h>
#include <ida.hpp>
#include <idp.hpp>
#include <ua.hpp>
#include <intel.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <segment.hpp>
#include <xref.hpp>

namespace viy {
namespace {

using deobf::Architecture;
using deobf::Block;
using deobf::ClassifierLimits;
using deobf::Instruction;
using deobf::InstructionKind;
using deobf::X86Condition;

Architecture detect_architecture()
{
  if ( PH.id == PLFM_386 )
    return Architecture::X86;
  if ( PH.id == PLFM_ARM )
    return inf_is_64bit() ? Architecture::Arm64 : Architecture::Arm32;
  return Architecture::Unsupported;
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

uint8_t operand_width(const op_t &op)
{
  size_t width = get_dtype_size(op.dtype);
  if ( width == 0 || width == size_t(-1) || width > 8 )
  {
    const size_t address_width = size_t(inf_get_app_bitness() / 8u);
    width = address_width >= 1 && address_width <= 8 ? address_width : 8;
  }
  return static_cast<uint8_t>(width);
}

std::string register_name(int reg, uint8_t width)
{
  if ( reg < 0 || width == 0 )
    return {};
  qstring out;
  if ( get_reg_name(&out, reg, width) < 0 )
    return {};
  std::string name(out.c_str());
  std::transform(name.begin(), name.end(), name.begin(),
                 [](unsigned char c)
                 { return static_cast<char>(std::tolower(c)); });
  return name;
}

std::string operand_register_name(const op_t &op)
{
  return op.type == o_reg ? register_name(op.reg, operand_width(op))
                          : std::string();
}

bool stack_register_name(const std::string &name)
{
  return name == "sp" || name == "esp" || name == "rsp";
}

bool stack_register_operand(const op_t &op)
{
  return op.type == o_reg && stack_register_name(operand_register_name(op));
}

bool x86_base_only_operand(const insn_t &insn, const op_t &op, int base)
{
  if ( op.type != o_phrase && op.type != o_displ )
    return false;
  if ( op.type == o_displ && op.addr != 0 )
    return false;
  return x86_base_reg(insn, op) == base
      && x86_index_reg(insn, op) == R_none;
}

bool stack_top_memory_operand(const insn_t &insn, const op_t &op)
{
  return x86_base_only_operand(insn, op, R_sp);
}

bool read_only_scalar(ea_t address, uint8_t width, uint64_t *out)
{
  if ( out == nullptr || address == BADADDR || width == 0 || width > 8
    || address > BADADDR - width )
  {
    return false;
  }
  const segment_t *segment = getseg(address);
  if ( segment == nullptr || (segment->perm & SEGPERM_WRITE) != 0 )
    return false;
  std::array<uint8_t, 8> bytes{};
  for ( uint8_t i = 0; i < width; ++i )
    if ( !is_mapped(address + i) || !is_loaded(address + i) )
      return false;
  if ( get_bytes(bytes.data(), width, address) != width )
    return false;

  uint64_t value = 0;
  if ( inf_is_be() )
  {
    for ( uint8_t i = 0; i < width; ++i )
      value = (value << 8) | bytes[i];
  }
  else
  {
    for ( uint8_t i = 0; i < width; ++i )
      value |= uint64_t(bytes[i]) << (unsigned(i) * 8u);
  }
  *out = value;
  return true;
}

uint64_t sign_extend_to_width(uint64_t value, uint8_t source_width,
                              uint8_t destination_width)
{
  if ( source_width == 0 || source_width >= destination_width
    || source_width >= 8 || destination_width > 8 )
  {
    return value;
  }
  const unsigned source_bits = unsigned(source_width) * 8u;
  const uint64_t source_mask = (uint64_t(1) << source_bits) - 1u;
  value &= source_mask;
  if ( (value & (uint64_t(1) << (source_bits - 1u))) != 0 )
    value |= ~source_mask;
  if ( destination_width < 8 )
    value &= (uint64_t(1) << (unsigned(destination_width) * 8u)) - 1u;
  return value;
}

uint64_t x86_extended_immediate(const op_t &immediate, uint8_t result_width)
{
  return sign_extend_to_width(immediate.value, operand_width(immediate),
                              result_width);
}

bool mapped_executable(ea_t address)
{
  if ( address == BADADDR || !is_mapped(address) || !is_loaded(address) )
    return false;
  const segment_t *segment = getseg(address);
  return segment != nullptr
      && ((segment->perm & SEGPERM_EXEC) != 0 || is_code(get_flags(address)));
}

bool architecture_aligned(Architecture arch, ea_t address)
{
  if ( arch == Architecture::Arm64 )
    return (address & 3) == 0;
  if ( arch == Architecture::Arm32 )
    return (address & 1) == 0; // IDA canonicalizes Thumb targets
  return true;
}

bool usable_target(Architecture arch, uint64_t address)
{
  if ( address > uint64_t(BADADDR) )
    return false;
  const ea_t ea = ea_t(address);
  return architecture_aligned(arch, ea) && mapped_executable(ea);
}

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
    default:      return X86Condition::Unknown;
  }
}

X86Condition arm_condition(uint16_t encoded)
{
  // ARM comparison sets C when no borrow; the core's x86-style subtraction
  // flag calls borrow "carry", hence CS/CC are intentionally inverted here.
  switch ( encoded & 0x0f )
  {
    case 0:  return X86Condition::Zero;           // EQ
    case 1:  return X86Condition::NotZero;        // NE
    case 2:  return X86Condition::NotCarry;       // CS/HS
    case 3:  return X86Condition::Carry;          // CC/LO
    case 4:  return X86Condition::Sign;            // MI
    case 5:  return X86Condition::NotSign;         // PL
    case 6:  return X86Condition::Overflow;        // VS
    case 7:  return X86Condition::NotOverflow;     // VC
    case 8:  return X86Condition::Above;           // HI
    case 9:  return X86Condition::BelowOrEqual;    // LS
    case 10: return X86Condition::GreaterOrEqual;  // GE
    case 11: return X86Condition::Less;            // LT
    case 12: return X86Condition::Greater;         // GT
    case 13: return X86Condition::LessOrEqual;     // LE
    default: return X86Condition::Unknown;         // AL/NV
  }
}

bool x86_preserves_flags(uint16_t itype)
{
  if ( x86_condition(itype) != X86Condition::Unknown )
    return true;
  switch ( itype )
  {
    case NN_mov:
    case NN_movsx:
    case NN_movzx:
    case NN_movsxd:
    case NN_lea:
    case NN_nop:
    case NN_push:
    case NN_pop:
    case NN_pusha:
    case NN_popa:
    case NN_pushf:
    case NN_pushfd:
    case NN_pushfq:
    case NN_xchg:
    case NN_bswap:
    case NN_call:
    case NN_jmp:
    case NN_jmpni:
    case NN_jmpfi:
    case NN_retn:
    case NN_retf:
    case NN_jcxz:
    case NN_jecxz:
    case NN_jrcxz:
      return true;
    default:
      return false;
  }
}

int first_changed_register(const insn_t &insn)
{
  const uint32_t feature = insn.get_canon_feature(PH);
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    const op_t &op = insn.ops[i];
    if ( op.type == o_void )
      break;
    if ( op.type == o_reg
      && (feature & (uint32_t(CF_CHG1) << unsigned(i))) != 0 )
      return op.reg;
  }
  return deobf::kNoRegister;
}

void set_destination(Instruction &out, const op_t &op)
{
  if ( op.type != o_reg )
    return;
  out.destination_register = op.reg;
  out.value_width = operand_width(op);
  out.destination_name = register_name(op.reg, out.value_width);
}

void set_source(Instruction &out, const op_t &op)
{
  if ( op.type != o_reg )
    return;
  out.source_register = op.reg;
  if ( out.value_width == 0 )
    out.value_width = operand_width(op);
  out.source_name = register_name(op.reg, operand_width(op));
}

bool writes_global_memory(const insn_t &insn)
{
  const uint32_t feature = insn.get_canon_feature(PH);
  for ( int i = 0; i < UA_MAXOP; ++i )
  {
    const op_t &op = insn.ops[i];
    if ( op.type == o_void )
      break;
    if ( op.type == o_mem
      && (feature & (uint32_t(CF_CHG1) << unsigned(i))) != 0 )
      return true;
  }
  return false;
}

Instruction translate_x86(const insn_t &insn)
{
  Instruction out;
  out.address = insn.ea;
  out.size = insn.size;
  out.writes_global_memory = writes_global_memory(insn);
  out.flag_effect = x86_preserves_flags(insn.itype)
                  ? deobf::FlagEffect::Preserve
                  : deobf::FlagEffect::UnknownWrite;

  const X86Condition condition = x86_condition(insn.itype);
  if ( condition != X86Condition::Unknown )
  {
    out.kind = InstructionKind::ConditionalBranch;
    out.condition = condition;
    out.target = branch_target(insn);
    return out;
  }
  if ( is_call_insn(insn) )
  {
    const ea_t target = branch_target(insn);
    out.kind = target == BADADDR ? InstructionKind::IndirectCall
                                 : InstructionKind::DirectCall;
    out.target = target;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_ret_insn(insn) )
  {
    out.kind = InstructionKind::Return;
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( insn.itype == NN_jmp || insn.itype == NN_jmpni
    || insn.itype == NN_jmpfi )
  {
    const ea_t target = branch_target(insn);
    out.kind = target == BADADDR ? InstructionKind::IndirectJump
                                 : InstructionKind::DirectJump;
    out.target = target;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_indirect_jump_insn(insn) )
  {
    out.kind = InstructionKind::IndirectJump;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_basic_block_end(insn, false) && branch_target(insn) != BADADDR )
  {
    // LOOP/JCXZ-family predicates are deliberately not evaluated, but they
    // must remain visible to wrapper/CFG shape classification.
    out.kind = InstructionKind::ConditionalBranch;
    out.target = branch_target(insn);
    out.condition = X86Condition::Unknown;
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }

  switch ( insn.itype )
  {
    case NN_nop:
      out.kind = InstructionKind::Nop;
      out.plumbing = true;
      return out;

    case NN_push:
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      if ( insn.Op1.type == o_reg )
      {
        out.kind = InstructionKind::PushRegister;
        set_source(out, insn.Op1);
      }
      else if ( insn.Op1.type == o_imm )
      {
        out.kind = InstructionKind::PushImmediate;
        const uint8_t source_width = operand_width(insn.Op1);
        out.value_width = static_cast<uint8_t>(inf_get_app_bitness() / 8u);
        out.immediate = sign_extend_to_width(
            insn.Op1.value, source_width, out.value_width);
      }
      return out;

    case NN_pop:
      out.kind = InstructionKind::PopRegister;
      set_destination(out, insn.Op1);
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      return out;

    case NN_mov:
      set_destination(out, insn.Op1);
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      if ( insn.Op1.type != o_reg )
        break;
      if ( insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::LoadImmediate;
        out.immediate = x86_extended_immediate(insn.Op2, out.value_width);
      }
      else if ( insn.Op2.type == o_reg )
      {
        out.kind = InstructionKind::CopyRegister;
        set_source(out, insn.Op2);
      }
      else if ( stack_top_memory_operand(insn, insn.Op2) )
      {
        out.kind = InstructionKind::ReadStackTop;
      }
      else if ( insn.Op2.type == o_mem )
      {
        uint64_t value = 0;
        if ( read_only_scalar(insn.Op2.addr, out.value_width, &value) )
        {
          out.kind = InstructionKind::LoadReadOnlyConstant;
          out.memory_address = insn.Op2.addr;
          out.immediate = value;
        }
      }
      return out;

    case NN_lea:
      set_destination(out, insn.Op1);
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_displ
        && x86_base_only_operand(insn, insn.Op2, insn.Op1.reg) )
      {
        out.kind = InstructionKind::AddImmediate;
        out.source_register = insn.Op1.reg;
        out.immediate = insn.Op2.addr;
      }
      else if ( insn.Op1.type == o_reg && insn.Op2.type == o_mem )
      {
        out.kind = InstructionKind::LoadAddress;
        out.immediate = insn.Op2.addr;
      }
      return out;

    case NN_inc:
    case NN_dec:
      set_destination(out, insn.Op1);
      out.kind = insn.itype == NN_inc ? InstructionKind::AddImmediate
                                      : InstructionKind::SubImmediate;
      out.immediate = 1;
      return out;

    case NN_add:
      if ( stack_top_memory_operand(insn, insn.Op1)
        && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::AddStackTopImmediate;
        out.value_width = operand_width(insn.Op1);
        out.immediate = x86_extended_immediate(insn.Op2, out.value_width);
        return out;
      }
      if ( stack_register_operand(insn.Op1) && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::AdjustStackPointerImmediate;
        out.value_width = operand_width(insn.Op1);
        out.immediate = x86_extended_immediate(insn.Op2, out.value_width);
        out.plumbing = true;
        return out;
      }
      [[fallthrough]];
    case NN_sub:
    case NN_xor:
    case NN_and:
    case NN_or:
    case NN_shl:
    case NN_sal:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        set_destination(out, insn.Op1);
        out.source_register = insn.Op1.reg;
        out.immediate = (insn.itype == NN_shl || insn.itype == NN_sal)
                      ? insn.Op2.value
                      : x86_extended_immediate(insn.Op2, out.value_width);
        if ( insn.itype == NN_add ) out.kind = InstructionKind::AddImmediate;
        else if ( insn.itype == NN_sub ) out.kind = InstructionKind::SubImmediate;
        else if ( insn.itype == NN_xor ) out.kind = InstructionKind::XorImmediate;
        else if ( insn.itype == NN_and ) out.kind = InstructionKind::AndImmediate;
        else if ( insn.itype == NN_or ) out.kind = InstructionKind::OrImmediate;
        else out.kind = InstructionKind::ShiftLeftImmediate;
        return out;
      }
      if ( (insn.itype == NN_xor || insn.itype == NN_sub)
        && insn.Op1.type == o_reg && insn.Op2.type == o_reg
        && insn.Op1.reg == insn.Op2.reg )
      {
        set_destination(out, insn.Op1);
        out.kind = InstructionKind::LoadImmediate;
        out.immediate = 0;
        return out;
      }
      break;

    case NN_cmp:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::CompareImmediate;
        set_destination(out, insn.Op1);
        out.immediate = x86_extended_immediate(insn.Op2, out.value_width);
        out.flag_effect = deobf::FlagEffect::KnownCompare;
        return out;
      }
      if ( insn.Op1.type == o_imm && insn.Op2.type == o_reg )
      {
        out.kind = InstructionKind::CompareImmediate;
        set_destination(out, insn.Op2);
        out.immediate = x86_extended_immediate(insn.Op1, out.value_width);
        out.register_is_left_operand = false;
        out.flag_effect = deobf::FlagEffect::KnownCompare;
        return out;
      }
      break;

    case NN_test:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::TestImmediate;
        set_destination(out, insn.Op1);
        out.immediate = x86_extended_immediate(insn.Op2, out.value_width);
        out.flag_effect = deobf::FlagEffect::KnownTest;
        return out;
      }
      break;
  }

  const int changed = first_changed_register(insn);
  if ( changed >= 0 )
  {
    out.destination_register = changed;
    out.value_width = operand_width(insn.Op1);
    out.destination_name = register_name(changed, out.value_width);
  }
  return out;
}

Instruction translate_arm(const insn_t &insn)
{
  Instruction out;
  out.address = insn.ea;
  out.size = insn.size;
  out.writes_global_memory = writes_global_memory(insn);
  out.flag_effect = deobf::FlagEffect::UnknownWrite;

  if ( is_call_insn(insn) )
  {
    const ea_t target = branch_target(insn);
    out.kind = target == BADADDR ? InstructionKind::IndirectCall
                                 : InstructionKind::DirectCall;
    out.target = target;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_ret_insn(insn) || insn.itype == ARM_ret )
  {
    out.kind = InstructionKind::Return;
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( insn.itype == ARM_b )
  {
    const uint16_t cond = uint16_t(insn.segpref & 0x0f);
    out.target = branch_target(insn);
    if ( cond < 14 )
    {
      out.kind = InstructionKind::ConditionalBranch;
      out.condition = arm_condition(cond);
    }
    else
    {
      out.kind = InstructionKind::DirectJump;
    }
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( insn.itype == ARM_br )
  {
    out.kind = InstructionKind::IndirectJump;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( insn.itype == ARM_blr )
  {
    out.kind = InstructionKind::IndirectCall;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_indirect_jump_insn(insn) )
  {
    out.kind = InstructionKind::IndirectJump;
    set_source(out, insn.Op1);
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }
  if ( is_basic_block_end(insn, false) && branch_target(insn) != BADADDR )
  {
    // CBZ/CBNZ/TBZ/TBNZ and processor-specific conditional branches are CFG
    // conditions even when this core does not model their predicate value.
    out.kind = InstructionKind::ConditionalBranch;
    out.target = branch_target(insn);
    out.condition = X86Condition::Unknown;
    out.flag_effect = deobf::FlagEffect::Preserve;
    return out;
  }

  switch ( insn.itype )
  {
    case ARM_nop:
      out.kind = InstructionKind::Nop;
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      return out;

    case ARM_mov:
      set_destination(out, insn.Op1);
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::LoadImmediate;
        out.immediate = insn.Op2.value;
      }
      else if ( insn.Op1.type == o_reg && insn.Op2.type == o_reg )
      {
        out.kind = InstructionKind::CopyRegister;
        set_source(out, insn.Op2);
      }
      return out;

    case ARM_movt:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        set_destination(out, insn.Op1);
        out.source_register = insn.Op1.reg;
        out.kind = InstructionKind::ReplaceHigh16;
        out.immediate = insn.Op2.value;
        out.flag_effect = deobf::FlagEffect::Preserve;
      }
      return out;

    case ARM_adr:
      if ( insn.Op1.type == o_reg )
      {
        set_destination(out, insn.Op1);
        out.kind = InstructionKind::LoadAddress;
        out.immediate = insn.Op2.addr != 0 ? insn.Op2.addr : insn.Op2.value;
        out.flag_effect = deobf::FlagEffect::Preserve;
        out.plumbing = true;
      }
      return out;

    case ARM_ldr:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_mem )
      {
        set_destination(out, insn.Op1);
        uint64_t value = 0;
        if ( read_only_scalar(insn.Op2.addr, out.value_width, &value) )
        {
          out.kind = InstructionKind::LoadReadOnlyConstant;
          out.memory_address = insn.Op2.addr;
          out.immediate = value;
        }
        out.flag_effect = deobf::FlagEffect::Preserve;
        out.plumbing = true;
      }
      return out;

    case ARM_add:
    case ARM_sub:
    case ARM_eor:
    case ARM_and:
    case ARM_orr:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_reg
        && insn.Op3.type == o_imm )
      {
        set_destination(out, insn.Op1);
        set_source(out, insn.Op2);
        out.immediate = insn.Op3.value;
        if ( insn.itype == ARM_add ) out.kind = InstructionKind::AddImmediate;
        else if ( insn.itype == ARM_sub ) out.kind = InstructionKind::SubImmediate;
        else if ( insn.itype == ARM_eor ) out.kind = InstructionKind::XorImmediate;
        else if ( insn.itype == ARM_and ) out.kind = InstructionKind::AndImmediate;
        else out.kind = InstructionKind::OrImmediate;
        return out;
      }
      break;

    case ARM_cmp:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::CompareImmediate;
        set_destination(out, insn.Op1);
        out.immediate = insn.Op2.value;
        out.flag_effect = deobf::FlagEffect::KnownCompare;
        return out;
      }
      break;

    case ARM_tst:
      if ( insn.Op1.type == o_reg && insn.Op2.type == o_imm )
      {
        out.kind = InstructionKind::TestImmediate;
        set_destination(out, insn.Op1);
        out.immediate = insn.Op2.value;
        out.flag_effect = deobf::FlagEffect::KnownTest;
        return out;
      }
      break;

    case ARM_push:
    case ARM_pop:
      out.flag_effect = deobf::FlagEffect::Preserve;
      out.plumbing = true;
      return out;
  }

  const int changed = first_changed_register(insn);
  if ( changed >= 0 )
  {
    out.destination_register = changed;
    out.value_width = operand_width(insn.Op1);
    out.destination_name = register_name(changed, out.value_width);
  }
  return out;
}

Instruction translate_instruction(Architecture arch, const insn_t &insn)
{
  return arch == Architecture::X86 ? translate_x86(insn)
                                   : translate_arm(insn);
}

bool has_alternate_predecessor(ea_t at, ea_t expected_linear)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_to(at, XREF_CODE); ok; ok = xb.next_to() )
  {
    if ( !xb.iscode )
      break;
    if ( xb.from != expected_linear )
      return true;
  }
  return false;
}

bool has_other_callers(ea_t target, ea_t caller)
{
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_CODE); ok; ok = xb.next_to() )
  {
    if ( !xb.iscode )
      break;
    if ( xb.from == caller )
      continue;
    insn_t incoming;
    if ( decode_insn(&incoming, xb.from) > 0 && is_call_insn(incoming) )
      return true;
  }
  return false;
}

size_t count_callers(ea_t target)
{
  size_t count = 0;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_CODE); ok; ok = xb.next_to() )
  {
    if ( !xb.iscode )
      break;
    insn_t incoming;
    if ( decode_insn(&incoming, xb.from) > 0 && is_call_insn(incoming) )
      ++count;
  }
  return count;
}

bool safe_gap(ea_t start, ea_t end, bool *loaded, bool *unreferenced)
{
  *loaded = start < end;
  *unreferenced = start < end;
  const segment_t *initial_segment = getseg(start);
  for ( ea_t ea = start; ea < end; ++ea )
  {
    if ( !is_mapped(ea) || !is_loaded(ea) || getseg(ea) != initial_segment )
      *loaded = false;
    const flags64_t flags = get_flags(ea);
    const func_t *function = get_func(ea);
    if ( has_xref(flags) || has_name(flags)
      || (function != nullptr && function->start_ea == ea) )
    {
      *unreferenced = false;
    }
  }
  return *loaded && *unreferenced;
}

std::vector<uint8_t> least_significant_bytes(uint64_t value, uint8_t width)
{
  if ( width == 0 || width > 8 )
    width = 8;
  std::vector<uint8_t> bytes(width);
  for ( uint8_t i = 0; i < width; ++i )
    bytes[i] = static_cast<uint8_t>(value >> (unsigned(i) * 8u));
  return bytes;
}

std::string hex_address(uint64_t address)
{
  std::ostringstream out;
  out << "0x" << std::hex << address;
  return out.str();
}

ClassifierLimits bounded_limits(ClassifierLimits limits)
{
  limits.gadget_depth = std::min<size_t>(limits.gadget_depth, 4096);
  limits.maximum_gap = std::min<uint64_t>(limits.maximum_gap, 1024u * 1024u);
  limits.entry_predicate_window =
      std::min<uint64_t>(limits.entry_predicate_window, 1024u * 1024u);
  limits.wrapper_maximum_instructions =
      std::min<size_t>(limits.wrapper_maximum_instructions, 4096);
  limits.minimum_constant_steps =
      std::max<size_t>(1, std::min<size_t>(limits.minimum_constant_steps, 4096));
  limits.maximum_dispatch_cases =
      std::min<size_t>(limits.maximum_dispatch_cases, 4096);
  return limits;
}

struct FunctionSnapshot
{
  func_t *function = nullptr;
  uint64_t scope_end = 0;
  std::vector<range_t> chunks;
  std::map<uint64_t, Instruction> instruction_by_address;
  std::vector<Instruction> instructions;
  std::vector<Block> blocks;
  bool scan_complete = true;
  bool blocks_complete = true;
};

} // anonymous namespace

struct DeobfAnalysisProvider::Impl
{
  using KeySet = std::set<std::vector<uint8_t>>;

  DeobfAnalysisFactSink &sink;
  Architecture architecture = Architecture::Unsupported;
  uint64_t current_epoch = 1;
  std::map<uint64_t, KeySet> emitted_by_function;

  explicit Impl(DeobfAnalysisFactSink &sink_) : sink(sink_)
  {
    architecture = detect_architecture();
  }

  bool emit(DeobfAnalysisStats &stats,
            const FunctionSnapshot &snapshot,
            const char *method,
            analysis::ProofKind proof,
            uint16_t confidence,
            analysis::FactPayload payload,
            std::vector<uint64_t> support,
            std::string detail)
  {
    std::string error;
    if ( !analysis::normalize_payload(payload, &error) )
      return false;
    std::vector<uint8_t> key;
    if ( !analysis::encode_payload(payload, key, &error) )
      return false;
    const uint64_t function_ea = snapshot.function == nullptr
                               ? deobf::kBadAddress
                               : uint64_t(snapshot.function->start_ea);
    KeySet &keys = emitted_by_function[function_ea];
    if ( keys.find(key) != keys.end() )
    {
      ++stats.facts_deduplicated;
      return false;
    }

    analysis::Evidence evidence;
    evidence.producer = "viy.deobf.ida";
    evidence.method = method;
    evidence.proof = proof;
    evidence.confidence = confidence;
    evidence.scope.generation = current_epoch;
    if ( snapshot.function != nullptr )
    {
      evidence.scope.function_start = snapshot.function->start_ea;
      if ( snapshot.scope_end > uint64_t(snapshot.function->start_ea) )
        evidence.scope.function_end = snapshot.scope_end;
    }
    evidence.support_addresses = std::move(support);
    evidence.detail = "deobf schema "
                    + std::to_string(kDeobfEvidenceSchemaVersion)
                    + "; " + detail;

    analysis::AnalysisFact fact{ std::move(payload), std::move(evidence) };
    if ( !analysis::normalize_fact(fact, &error) )
      return false;
    if ( !sink.emit_deobf_fact(fact) )
      return false;
    keys.insert(std::move(key));
    ++stats.facts_emitted;
    return true;
  }

  bool snapshot_function(FunctionSnapshot &out,
                         func_t *function,
                         const DeobfAnalysisOptions &options,
                         DeobfAnalysisStats &stats)
  {
    if ( function == nullptr || function->start_ea == BADADDR )
      return false;
    out.function = function;
    out.scope_end = function->end_ea;
    const size_t hard_instruction_limit = options.max_instructions_per_function == 0
        ? size_t(1000000) : options.max_instructions_per_function;
    bool budget_exhausted = false;

    func_tail_iterator_t chunks(function);
    for ( bool ok = chunks.main(); ok; ok = chunks.next() )
    {
      const range_t range = chunks.chunk();
      if ( range.empty() )
        continue;
      out.chunks.push_back(range);
      out.scope_end = std::max(out.scope_end, uint64_t(range.end_ea));
      ++stats.chunks_scanned;

      ea_t previous_instruction = BADADDR;
      ea_t expected_linear = range.start_ea;
      ea_t ea = range.start_ea;
      while ( ea != BADADDR && ea < range.end_ea )
      {
        if ( out.instructions.size() >= hard_instruction_limit )
        {
          out.scan_complete = false;
          budget_exhausted = true;
          ++stats.budget_truncations;
          break;
        }
        const flags64_t flags = get_flags(ea);
        if ( is_head(flags) && is_code(flags) )
        {
          if ( ea != expected_linear )
            out.scan_complete = false;
          insn_t decoded;
          if ( decode_insn(&decoded, ea) > 0 && decoded.size != 0 )
          {
            Instruction instruction =
                translate_instruction(architecture, decoded);
            instruction.alternate_predecessor =
                has_alternate_predecessor(ea, previous_instruction);
            previous_instruction = decoded.ea;
            expected_linear = decoded.ea + decoded.size;
            out.instruction_by_address.emplace(instruction.address, instruction);
            out.instructions.push_back(std::move(instruction));
            ++stats.instructions_scanned;
          }
          else
          {
            ++stats.decode_failures;
            out.scan_complete = false;
            previous_instruction = BADADDR;
          }
        }
        const ea_t next = next_head(ea, range.end_ea);
        if ( next == BADADDR || next <= ea )
          break;
        ea = next;
      }
      if ( expected_linear != range.end_ea )
        out.scan_complete = false;
      if ( budget_exhausted )
        break;
    }

    std::sort(out.instructions.begin(), out.instructions.end(),
              [](const Instruction &a, const Instruction &b)
              { return a.address < b.address; });
    build_blocks(out, options, stats);
    return true;
  }

  void build_blocks(FunctionSnapshot &snapshot,
                    const DeobfAnalysisOptions &options,
                    DeobfAnalysisStats &stats)
  {
    if ( snapshot.chunks.empty() )
      return;
    rangevec_t ranges;
    for ( const range_t &range : snapshot.chunks )
      ranges.push_back(range);
    qflow_chart_t flow;
    flow.create("viy-deobf-readonly", ranges, FC_NOEXT);
    const size_t hard_block_limit = options.max_blocks_per_function == 0
        ? size_t(100000) : options.max_blocks_per_function;
    if ( size_t(flow.size()) > hard_block_limit )
    {
      snapshot.blocks_complete = false;
      ++stats.budget_truncations;
    }
    const size_t count = std::min<size_t>(size_t(flow.size()), hard_block_limit);
    snapshot.blocks.reserve(count);
    for ( size_t i = 0; i < count; ++i )
    {
      const qbasic_block_t &source = flow.blocks[i];
      Block block;
      block.start = source.start_ea;
      block.end = source.end_ea;
      block.predecessor_count = source.pred.size();
      for ( int successor : source.succ )
      {
        if ( successor >= 0 && size_t(successor) < size_t(flow.size()) )
          block.successors.push_back(flow.blocks[size_t(successor)].start_ea);
      }
      auto instruction = snapshot.instruction_by_address.lower_bound(block.start);
      uint64_t expected = block.start;
      bool block_complete = true;
      while ( instruction != snapshot.instruction_by_address.end()
           && instruction->first < block.end )
      {
        if ( instruction->first != expected )
          block_complete = false;
        block.instructions.push_back(instruction->second);
        expected = instruction->second.end();
        ++instruction;
      }
      if ( expected != block.end )
        block_complete = false;
      if ( !block.instructions.empty() && block_complete )
      {
        snapshot.blocks.push_back(std::move(block));
        ++stats.blocks_scanned;
      }
      else if ( !block_complete )
      {
        snapshot.blocks_complete = false;
      }
    }
  }

  std::vector<Instruction> decode_gadget(ea_t target,
                                         const ClassifierLimits &limits)
  {
    std::vector<Instruction> out;
    ea_t ea = target;
    ea_t previous = BADADDR;
    for ( size_t i = 0; i <= limits.gadget_depth; ++i )
    {
      if ( !mapped_executable(ea) )
        break;
      insn_t decoded;
      if ( decode_insn(&decoded, ea) <= 0 || decoded.size == 0 )
        break;
      Instruction instruction = translate_instruction(architecture, decoded);
      instruction.alternate_predecessor =
          has_alternate_predecessor(ea, previous);
      out.push_back(instruction);
      previous = ea;
      if ( instruction.kind == InstructionKind::Return
        || instruction.kind == InstructionKind::DirectCall
        || instruction.kind == InstructionKind::IndirectCall
        || instruction.kind == InstructionKind::DirectJump
        || instruction.kind == InstructionKind::IndirectJump
        || instruction.kind == InstructionKind::ConditionalBranch )
      {
        break;
      }
      if ( ea > BADADDR - decoded.size )
        break;
      ea += decoded.size;
    }
    return out;
  }

  void analyze_get_pc(DeobfAnalysisStats &stats,
                      const FunctionSnapshot &snapshot,
                      const ClassifierLimits &limits)
  {
    if ( architecture != Architecture::X86 )
      return;
    for ( const Instruction &call : snapshot.instructions )
    {
      if ( call.kind != InstructionKind::DirectCall
        || call.target == deobf::kBadAddress )
      {
        continue;
      }
      std::vector<Instruction> gadget = decode_gadget(ea_t(call.target), limits);
      const auto candidate = deobf::classify_get_pc_gadget(
          call, gadget, has_other_callers(ea_t(call.target), ea_t(call.address)),
          limits);
      if ( !candidate.has_value() )
        continue;

      std::ostringstream description;
      description << "get-pc:gadget=" << hex_address(candidate->gadget)
                  << ":mode=" << unsigned(candidate->mode);
      if ( candidate->resumed_at.has_value() )
        description << ":resume=" << hex_address(*candidate->resumed_at);
      analysis::FunctionTraitFact trait;
      trait.function = snapshot.function->start_ea;
      trait.trait = analysis::FunctionTraitKind::Other;
      trait.value = analysis::TraitValue::text(description.str());
      if ( emit(stats, snapshot, "x86.get_pc.call_gadget",
                analysis::ProofKind::StaticProof, 9800, trait,
                candidate->support,
                "bounded call-target gadget consumes or reads the pushed return address") )
      {
        ++stats.get_pc_gadgets;
      }

      if ( candidate->register_value_at_return.has_value()
        && candidate->return_instruction != deobf::kBadAddress
        && !candidate->pc_register_name.empty() )
      {
        analysis::RegisterValueFact value;
        value.instruction = candidate->return_instruction;
        value.point = analysis::RegisterStatePoint::BeforeInstruction;
        value.register_id = candidate->pc_register_name;
        const uint8_t width = gadget.empty() ? 8 : gadget.front().value_width;
        value.bytes = least_significant_bytes(
            *candidate->register_value_at_return, width);
        emit(stats, snapshot, "x86.get_pc.register_value",
             analysis::ProofKind::StaticProof, 9800, value,
             candidate->support,
             "return address value propagated through the bounded gadget");
      }

      if ( candidate->resumed_at.has_value()
        && candidate->return_instruction != deobf::kBadAddress
        && usable_target(architecture, *candidate->resumed_at) )
      {
        analysis::CodeTargetFact target;
        target.from = candidate->return_instruction;
        target.target = *candidate->resumed_at;
        target.kind = analysis::CodeTargetKind::Return;
        target.unique = true;
        emit(stats, snapshot, "x86.get_pc.push_return_target",
             analysis::ProofKind::StaticProof, 9900, target,
             candidate->support,
             "push/adjust-return gadget has one exact resumed address");

        analysis::BranchReachabilityFact reached;
        reached.branch = candidate->return_instruction;
        reached.successor = *candidate->resumed_at;
        reached.state = analysis::Reachability::Reached;
        emit(stats, snapshot, "x86.get_pc.push_return_target",
             analysis::ProofKind::StaticProof, 9900, reached,
             candidate->support,
             "push/adjust-return gadget reaches the computed continuation");
      }

      const uint64_t gap_start = call.end();
      if ( gap_start != deobf::kBadAddress && call.target > gap_start
        && call.target - gap_start <= limits.maximum_gap )
      {
        bool loaded = false;
        bool unreferenced = false;
        if ( safe_gap(ea_t(gap_start), ea_t(call.target),
                      &loaded, &unreferenced) )
        {
          analysis::CodeRegionFact region;
          region.start = gap_start;
          region.end = call.target;
          region.kind = analysis::CodeRegionKind::Data;
          if ( emit(stats, snapshot, "x86.get_pc.skipped_gap",
                    analysis::ProofKind::Heuristic, 7000, region,
                    { call.address, gap_start, call.target },
                    "unreferenced loaded bytes skipped by a bounded get-PC gadget call") )
          {
            ++stats.code_region_candidates;
          }
        }
      }
    }
  }

  void analyze_jump_gaps(DeobfAnalysisStats &stats,
                         const FunctionSnapshot &snapshot,
                         const ClassifierLimits &limits)
  {
    for ( const Instruction &instruction : snapshot.instructions )
    {
      if ( instruction.kind != InstructionKind::DirectJump )
        continue;
      const uint64_t start = instruction.end();
      if ( start == deobf::kBadAddress || instruction.target <= start
        || instruction.target - start > limits.maximum_gap )
      {
        continue;
      }
      bool loaded = false;
      bool unreferenced = false;
      safe_gap(ea_t(start), ea_t(instruction.target), &loaded, &unreferenced);
      const auto gap = deobf::classify_jump_gap(
          instruction, loaded, unreferenced, limits);
      if ( !gap.has_value() )
        continue;
      analysis::CodeRegionFact region;
      region.start = gap->start;
      region.end = gap->end;
      region.kind = analysis::CodeRegionKind::Data;
      if ( emit(stats, snapshot, "cfg.jump_over_unreferenced_gap",
                analysis::ProofKind::Heuristic, 7000, region,
                { gap->branch, gap->start, gap->end },
                "forward unconditional branch skips a bounded loaded range with no names or inbound references") )
      {
        ++stats.code_region_candidates;
      }
    }
  }

  void analyze_entry_predicate(DeobfAnalysisStats &stats,
                               const FunctionSnapshot &snapshot,
                               const ClassifierLimits &limits)
  {
    const Block *entry = nullptr;
    for ( const Block &block : snapshot.blocks )
      if ( block.start == uint64_t(snapshot.function->start_ea) )
      {
        entry = &block;
        break;
      }
    if ( entry == nullptr )
      return;
    const auto predicate = deobf::classify_entry_predicate(
        snapshot.function->start_ea, entry->instructions, limits);
    if ( !predicate.has_value() )
      return;

    if ( predicate->knowledge == deobf::PredicateKnowledge::EntryFlagsUnspecified )
    {
      // This structural heuristic is meaningful for x86 ABIs only.  It is an
      // annotation, never a reachability assertion: entry EFLAGS are arbitrary.
      if ( architecture != Architecture::X86 )
        return;
      analysis::FunctionTraitFact trait;
      trait.function = snapshot.function->start_ea;
      trait.trait = analysis::FunctionTraitKind::Other;
      trait.value = analysis::TraitValue::text(
          "entry-predicate:arithmetic-flags-unspecified:branch="
          + hex_address(predicate->branch));
      if ( emit(stats, snapshot, "entry.flags_unspecified",
                analysis::ProofKind::Heuristic, 7200, trait,
                predicate->support,
                "conditional branch consumes ABI-unspecified entry flags before any local flag definition") )
      {
        ++stats.entry_predicates;
      }
      return;
    }

    if ( predicate->knowledge != deobf::PredicateKnowledge::ConstantOutcome
      || !predicate->taken.has_value() || predicate->support.size() < 3 )
    {
      return;
    }
    if ( !usable_target(architecture, predicate->target)
      || !usable_target(architecture, predicate->fallthrough) )
    {
      return;
    }
    const uint64_t reached_ea = *predicate->taken
                              ? predicate->target : predicate->fallthrough;
    const uint64_t unreachable_ea = *predicate->taken
                                  ? predicate->fallthrough : predicate->target;
    analysis::BranchReachabilityFact reached;
    reached.branch = predicate->branch;
    reached.successor = reached_ea;
    reached.state = analysis::Reachability::Reached;
    if ( emit(stats, snapshot, "entry.constant_compare",
              analysis::ProofKind::StaticProof, 9900, reached,
              predicate->support,
              "entry-local constant chain makes the comparison outcome exact") )
    {
      ++stats.constant_predicates;
    }
    analysis::BranchReachabilityFact unreachable;
    unreachable.branch = predicate->branch;
    unreachable.successor = unreachable_ea;
    unreachable.state = analysis::Reachability::ProvenUnreachable;
    emit(stats, snapshot, "entry.constant_compare",
         analysis::ProofKind::StaticProof, 9900, unreachable,
         predicate->support,
         "opposite edge is excluded by an exact width-aware comparison");
  }

  void analyze_wrapper(DeobfAnalysisStats &stats,
                       const FunctionSnapshot &snapshot,
                       const ClassifierLimits &limits)
  {
    deobf::FunctionShape shape;
    shape.entry = snapshot.function->start_ea;
    shape.end = snapshot.scope_end;
    shape.instructions = snapshot.instructions;
    shape.caller_count = count_callers(snapshot.function->start_ea);
    shape.has_tail_chunks = snapshot.chunks.size() > 1;
    shape.scan_complete = snapshot.scan_complete;
    shape.already_special = (snapshot.function->flags
        & (FUNC_LIB | FUNC_THUNK | FUNC_HIDDEN | FUNC_OUTLINE)) != 0;
    for ( const Instruction &instruction : shape.instructions )
    {
      if ( instruction.kind == InstructionKind::DirectCall
        && instruction.target != deobf::kBadAddress )
      {
        const func_t *callee = get_func(ea_t(instruction.target));
        shape.direct_callee_returns = callee == nullptr || callee->does_return();
        break;
      }
    }
    const auto wrapper = deobf::classify_wrapper(shape, limits);
    if ( !wrapper.has_value() || wrapper->target == wrapper->function
      || !usable_target(architecture, wrapper->target) )
    {
      return;
    }

    analysis::FunctionTraitFact target;
    target.function = wrapper->function;
    target.trait = analysis::FunctionTraitKind::WrapperTarget;
    target.value = analysis::TraitValue::unsigned_integer(wrapper->target);
    if ( emit(stats, snapshot, "cfg.wrapper_shape",
              analysis::ProofKind::Heuristic, 8500, target,
              { wrapper->function, wrapper->target },
              "bounded small function has one direct transfer and no global writes or conditional flow") )
    {
      ++stats.wrapper_traits;
    }
    if ( wrapper->thunk )
    {
      analysis::FunctionTraitFact thunk;
      thunk.function = wrapper->function;
      thunk.trait = analysis::FunctionTraitKind::Thunk;
      thunk.value = analysis::TraitValue::none();
      emit(stats, snapshot, "cfg.thunk_shape",
           analysis::ProofKind::Heuristic, 9000, thunk,
           { wrapper->function, wrapper->target },
           wrapper->tail_call
             ? "plumbing-only function ends in one direct tail transfer"
             : "plumbing-only function wraps one direct call and return");
    }
  }

  std::map<uint64_t, deobf::ConstantBlockResult> analyze_constants(
      DeobfAnalysisStats &stats,
      const FunctionSnapshot &snapshot,
      const ClassifierLimits &limits,
      bool emit_indirect_targets,
      bool emit_push_return_targets)
  {
    std::map<uint64_t, deobf::ConstantBlockResult> results;
    for ( const Block &block : snapshot.blocks )
    {
      deobf::ConstantBlockResult result =
          deobf::analyze_constant_block(block, limits);
      if ( emit_indirect_targets || emit_push_return_targets )
      {
        for ( const deobf::ConstantTargetCandidate &candidate : result.targets )
        {
          if ( candidate.kind == deobf::ConstantTargetKind::PushReturn
            ? !emit_push_return_targets : !emit_indirect_targets )
          {
            continue;
          }
          if ( !usable_target(architecture, candidate.target) )
            continue;
          analysis::CodeTargetFact target;
          target.from = candidate.instruction;
          target.target = candidate.target;
          target.unique = true;
          if ( candidate.kind == deobf::ConstantTargetKind::IndirectCall )
            target.kind = analysis::CodeTargetKind::Call;
          else if ( candidate.kind == deobf::ConstantTargetKind::IndirectJump )
            target.kind = analysis::CodeTargetKind::Jump;
          else
            target.kind = analysis::CodeTargetKind::Return;
          const char *method = candidate.kind == deobf::ConstantTargetKind::PushReturn
                             ? "x86.push_ret.constant_target"
                             : "constant_chain.indirect_target";
          if ( emit(stats, snapshot, method,
                    analysis::ProofKind::StaticProof, 9900, target,
                    candidate.support,
                    "width-bounded same-block constant chain yields one executable target") )
          {
            if ( candidate.kind == deobf::ConstantTargetKind::PushReturn )
              ++stats.push_return_targets;
            else
              ++stats.constant_targets;
          }

          if ( candidate.register_id != deobf::kNoRegister
            && !candidate.register_name.empty() )
          {
            analysis::RegisterValueFact value;
            value.instruction = candidate.instruction;
            value.point = analysis::RegisterStatePoint::BeforeInstruction;
            value.register_id = candidate.register_name;
            value.bytes = least_significant_bytes(candidate.target,
                                                  candidate.value_width);
            emit(stats, snapshot, "constant_chain.register_value",
                 analysis::ProofKind::StaticProof, 9900, value,
                 candidate.support,
                 "same-block constant chain fixes the transfer register value");
          }
        }
      }
      results.emplace(block.start, std::move(result));
    }
    return results;
  }

  void analyze_dispatch(DeobfAnalysisStats &stats,
                        const FunctionSnapshot &snapshot,
                        const ClassifierLimits &limits,
                        const std::map<uint64_t,
                          deobf::ConstantBlockResult> &constants)
  {
    if ( !snapshot.scan_complete || !snapshot.blocks_complete )
      return;
    const std::vector<deobf::DispatchCandidate> dispatchers =
        deobf::find_dispatch_candidates(snapshot.blocks, limits);
    for ( const deobf::DispatchCandidate &candidate : dispatchers )
    {
      analysis::DispatchMapFact map;
      map.site = candidate.site;
      for ( const deobf::DispatchCaseCandidate &item : candidate.cases )
        map.cases.push_back({ item.selector, item.target });
      map.default_target = candidate.default_target;
      map.complete = false;
      std::ostringstream detail;
      detail << "static comparison-chain dispatch candidate; cases="
             << candidate.cases.size() << "; selector-one-bits="
             << unsigned(candidate.selector_one_bit_percent) << "%"
             << "; loop-backed=" << (candidate.loop_backed ? "yes" : "no")
             << "; completeness deliberately unasserted";
      if ( emit(stats, snapshot, "cfg.dispatch.compare_chain",
                analysis::ProofKind::Heuristic,
                candidate.loop_backed ? 9000 : 8000,
                map, candidate.comparison_sites, detail.str()) )
      {
        ++stats.dispatch_maps;
      }

      if ( candidate.loop_backed
        && candidate.selector_one_bit_percent >= 20
        && candidate.selector_one_bit_percent <= 80 )
      {
        analysis::FunctionTraitFact trait;
        trait.function = snapshot.function->start_ea;
        trait.trait = analysis::FunctionTraitKind::Other;
        trait.value = analysis::TraitValue::text(
            "cff-dispatch-candidate:site=" + hex_address(candidate.site)
            + ":cases=" + std::to_string(candidate.cases.size()));
        emit(stats, snapshot, "cfg.dispatch.cff_shape",
             analysis::ProofKind::Heuristic, 8800, trait,
             candidate.comparison_sites,
             "loop-backed high-entropy state comparison chain resembles flattened control flow");
      }

      std::map<uint64_t, uint64_t> target_by_selector;
      for ( const deobf::DispatchCaseCandidate &item : candidate.cases )
        target_by_selector[item.selector] = item.target;
      for ( const Block &block : snapshot.blocks )
      {
        if ( block.successors.size() != 1
          || block.successors.front() != candidate.entry_block
          || block.instructions.empty() )
        {
          continue;
        }
        const auto block_constants = constants.find(block.start);
        if ( block_constants == constants.end() )
          continue;
        for ( const deobf::ConstantAssignment &assignment :
              block_constants->second.final_assignments )
        {
          if ( assignment.register_id != candidate.state_register
            || assignment.value_width != candidate.state_width )
            continue;
          const auto destination = target_by_selector.find(assignment.value);
          if ( destination == target_by_selector.end() )
            continue;
          analysis::CfgCandidateFact edge;
          edge.from = block.instructions.back().address;
          edge.to = destination->second;
          edge.kind = analysis::CfgEdgeKind::Indirect;
          edge.state = analysis::Reachability::Reached;
          std::vector<uint64_t> support = assignment.support;
          support.insert(support.end(), candidate.comparison_sites.begin(),
                         candidate.comparison_sites.end());
          if ( emit(stats, snapshot, "cfg.dispatch.constant_state_edge",
                    analysis::ProofKind::SymbolicProof, 9500, edge,
                    std::move(support),
                    "single-successor predecessor fixes the dispatch state to one mapped case") )
          {
            ++stats.cff_edge_candidates;
          }
        }
      }
    }
  }

  bool analyze_one(DeobfAnalysisStats &stats,
                   func_t *function,
                   const DeobfAnalysisOptions &options)
  {
    FunctionSnapshot snapshot;
    if ( !snapshot_function(snapshot, function, options, stats) )
      return false;
    ++stats.functions_scanned;
    const ClassifierLimits limits = bounded_limits(options.classifier_limits);

    if ( options.detect_get_pc_gadgets )
      analyze_get_pc(stats, snapshot, limits);
    if ( options.detect_jump_gaps )
      analyze_jump_gaps(stats, snapshot, limits);
    if ( options.detect_entry_predicates )
      analyze_entry_predicate(stats, snapshot, limits);
    if ( options.detect_wrappers )
      analyze_wrapper(stats, snapshot, limits);

    const bool need_constants = options.resolve_constant_chains
                             || options.detect_push_return_gadgets
                             || options.detect_dispatch_maps;
    std::map<uint64_t, deobf::ConstantBlockResult> constants;
    if ( need_constants )
    {
      constants = analyze_constants(
          stats, snapshot, limits,
          options.resolve_constant_chains,
          options.detect_push_return_gadgets);
    }
    if ( options.detect_dispatch_maps )
      analyze_dispatch(stats, snapshot, limits, constants);
    return true;
  }

  DeobfAnalysisStats analyze_database(const DeobfAnalysisOptions &options)
  {
    architecture = detect_architecture();
    DeobfAnalysisStats stats;
    stats.architecture = architecture;
    stats.epoch = current_epoch;
    if ( architecture == Architecture::Unsupported )
      return stats;
    const size_t count = get_func_qty();
    const size_t limit = options.max_functions == 0
                       ? count : std::min(count, options.max_functions);
    for ( size_t i = 0; i < limit; ++i )
      analyze_one(stats, getn_func(i), options);
    return stats;
  }

  DeobfAnalysisStats analyze_function(uint64_t any_ea,
                                      const DeobfAnalysisOptions &options)
  {
    architecture = detect_architecture();
    DeobfAnalysisStats stats;
    stats.architecture = architecture;
    stats.epoch = current_epoch;
    if ( architecture == Architecture::Unsupported
      || any_ea > uint64_t(BADADDR) )
    {
      return stats;
    }
    analyze_one(stats, get_func(ea_t(any_ea)), options);
    return stats;
  }
};

DeobfAnalysisProvider::DeobfAnalysisProvider(DeobfAnalysisFactSink &sink)
  : impl_(std::make_unique<Impl>(sink))
{
}

DeobfAnalysisProvider::~DeobfAnalysisProvider() = default;
DeobfAnalysisProvider::DeobfAnalysisProvider(
    DeobfAnalysisProvider &&) noexcept = default;
DeobfAnalysisProvider &DeobfAnalysisProvider::operator=(
    DeobfAnalysisProvider &&) noexcept = default;

DeobfAnalysisStats DeobfAnalysisProvider::analyze_database(
    const DeobfAnalysisOptions &options)
{
  return impl_->analyze_database(options);
}

DeobfAnalysisStats DeobfAnalysisProvider::analyze_function(
    uint64_t any_ea, const DeobfAnalysisOptions &options)
{
  return impl_->analyze_function(any_ea, options);
}

void DeobfAnalysisProvider::advance_epoch()
{
  if ( impl_->current_epoch != std::numeric_limits<uint64_t>::max() )
    ++impl_->current_epoch;
}

void DeobfAnalysisProvider::set_epoch(uint64_t epoch)
{
  impl_->current_epoch = epoch == 0 ? 1 : epoch;
}

void DeobfAnalysisProvider::invalidate_function(uint64_t any_ea)
{
  uint64_t function_ea = any_ea;
  if ( any_ea <= uint64_t(BADADDR) )
  {
    const func_t *function = get_func(ea_t(any_ea));
    if ( function != nullptr )
      function_ea = function->start_ea;
  }
  impl_->emitted_by_function.erase(function_ea);
  advance_epoch();
}

void DeobfAnalysisProvider::reset()
{
  impl_->emitted_by_function.clear();
  advance_epoch();
}

uint64_t DeobfAnalysisProvider::epoch() const
{
  return impl_->current_epoch;
}

} // namespace viy
