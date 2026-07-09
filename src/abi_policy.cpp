#include "abi_policy.hpp"

#include <algorithm>
#include <limits>

namespace viy {

namespace {

bool checked_add(uint64_t lhs, uint64_t rhs, uint64_t *out)
{
  if ( out == nullptr || lhs > std::numeric_limits<uint64_t>::max() - rhs )
    return false;
  *out = lhs + rhs;
  return true;
}

const ViyAbiLayout unknown{};
const ViyAbiLayout x86_32{
  ViyAbi::X86_32, "x86-32 stack", 4, true, 0, {}, {}
};
const ViyAbiLayout x64_sysv{
  ViyAbi::X86_64_SYSV, "x86-64 SysV", 8, true, 0,
  { RAX_X86_REG_RDI, RAX_X86_REG_RSI, RAX_X86_REG_RDX,
    RAX_X86_REG_RCX, RAX_X86_REG_R8, RAX_X86_REG_R9 },
  { "rdi", "rsi", "rdx", "rcx", "r8", "r9" }
};
const ViyAbiLayout x64_win{
  ViyAbi::X86_64_WIN64, "x86-64 Windows", 8, true, 32,
  { RAX_X86_REG_RCX, RAX_X86_REG_RDX, RAX_X86_REG_R8, RAX_X86_REG_R9 },
  { "rcx", "rdx", "r8", "r9" }
};
const ViyAbiLayout aapcs32{
  ViyAbi::AAPCS32, "AAPCS32", 4, false, 0,
  { RAX_ARM_R(0), RAX_ARM_R(1), RAX_ARM_R(2), RAX_ARM_R(3) },
  { "R0", "R1", "R2", "R3" }
};
const ViyAbiLayout aapcs64{
  ViyAbi::AAPCS64, "AAPCS64", 8, false, 0,
  { RAX_ARM64_X(0), RAX_ARM64_X(1), RAX_ARM64_X(2), RAX_ARM64_X(3),
    RAX_ARM64_X(4), RAX_ARM64_X(5), RAX_ARM64_X(6), RAX_ARM64_X(7) },
  { "X0", "X1", "X2", "X3", "X4", "X5", "X6", "X7" }
};
const ViyAbiLayout riscv64{
  ViyAbi::RISCV64, "RISC-V LP64", 8, false, 0,
  { RAX_RISCV_X(10), RAX_RISCV_X(11), RAX_RISCV_X(12), RAX_RISCV_X(13),
    RAX_RISCV_X(14), RAX_RISCV_X(15), RAX_RISCV_X(16), RAX_RISCV_X(17) },
  { "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7" }
};
const ViyAbiLayout cortex_m{
  ViyAbi::CORTEX_M, "Cortex-M AAPCS", 4, false, 0,
  { RAX_CM_R(0), RAX_CM_R(1), RAX_CM_R(2), RAX_CM_R(3) },
  { "R0", "R1", "R2", "R3" }
};
const ViyAbiLayout hexagon{
  ViyAbi::HEXAGON, "Hexagon", 4, false, 0,
  { RAX_HEX_R(0), RAX_HEX_R(1), RAX_HEX_R(2),
    RAX_HEX_R(3), RAX_HEX_R(4), RAX_HEX_R(5) },
  { "R0", "R1", "R2", "R3", "R4", "R5" }
};

} // namespace

ViyAbi viy_abi_for_arch(ViyArch arch, bool windows_x64)
{
  switch ( arch )
  {
    case ViyArch::X86_32:  return ViyAbi::X86_32;
    case ViyArch::X86_64:  return windows_x64 ? ViyAbi::X86_64_WIN64
                                              : ViyAbi::X86_64_SYSV;
    case ViyArch::ARM32:   return ViyAbi::AAPCS32;
    case ViyArch::ARM64:   return ViyAbi::AAPCS64;
    case ViyArch::RISCV64: return ViyAbi::RISCV64;
    case ViyArch::CORTEX_M:return ViyAbi::CORTEX_M;
    case ViyArch::HEXAGON: return ViyAbi::HEXAGON;
    default:               return ViyAbi::UNKNOWN;
  }
}

const ViyAbiLayout &viy_abi_layout(ViyAbi abi)
{
  switch ( abi )
  {
    case ViyAbi::X86_32:       return x86_32;
    case ViyAbi::X86_64_SYSV:  return x64_sysv;
    case ViyAbi::X86_64_WIN64: return x64_win;
    case ViyAbi::AAPCS32:      return aapcs32;
    case ViyAbi::AAPCS64:      return aapcs64;
    case ViyAbi::RISCV64:      return riscv64;
    case ViyAbi::CORTEX_M:     return cortex_m;
    case ViyAbi::HEXAGON:      return hexagon;
    default:                   return unknown;
  }
}

const char *viy_abi_name(ViyAbi abi)
{
  return viy_abi_layout(abi).name;
}

std::vector<ViySeedValue> viy_seed_argument_corpus(
    uint64_t seed, size_t count, uint64_t image_lo,
    uint64_t stack_base, uint64_t stack_size)
{
  std::vector<ViySeedValue> result;
  result.reserve(count);
  uint64_t mixed = seed * 0x9E3779B97F4A7C15ull + 0x1234567u;
  uint64_t stack_end = 0;
  uint64_t stack_middle = 0;
  const bool stack_mapped = stack_size != 0
                         && checked_add(stack_base, stack_size, &stack_end)
                         && checked_add(stack_base, stack_size / 2, &stack_middle)
                         && stack_middle < stack_end;

  for ( size_t index = 0; index < count; ++index )
  {
    mixed ^= mixed >> 33;
    mixed *= 0xFF51AFD7ED558CCDull;
    mixed ^= mixed >> 33;
    ViySeedValue item;
    switch ( (seed + uint64_t(index)) % 8 )
    {
      case 0: item = { 0, ViySeedValueKind::ZERO }; break;
      case 1: item = { 1, ViySeedValueKind::ONE }; break;
      case 2: item = { std::numeric_limits<uint16_t>::max(),
                       ViySeedValueKind::U16_MAX }; break;
      case 3: item = { uint64_t(std::numeric_limits<int16_t>::max()),
                       ViySeedValueKind::I16_MAX }; break;
      case 4: item = { uint64_t(int64_t(std::numeric_limits<int16_t>::min())),
                       ViySeedValueKind::I16_MIN }; break;
      case 5: item = { image_lo, ViySeedValueKind::IMAGE_POINTER }; break;
      case 6:
      {
        if ( !stack_mapped )
        {
          item = { mixed, ViySeedValueKind::MIXED };
          break;
        }
        const uint64_t span = stack_end - stack_middle;
        // Keep the useful 0x100 spacing but wrap for arbitrary argument counts.
        // ceil(span/0x100) is overflow-safe and every selected slot is < span.
        const uint64_t slots = 1 + (span - 1) / 0x100;
        const uint64_t slot = uint64_t(index) % slots;
        uint64_t pointer = stack_middle;
        if ( !checked_add(stack_middle, slot * 0x100, &pointer)
          || pointer >= stack_end )
          item = { mixed, ViySeedValueKind::MIXED };
        else
          item = { pointer, ViySeedValueKind::STACK_POINTER };
        break;
      }
      default: item = { mixed, ViySeedValueKind::MIXED }; break;
    }
    result.push_back(item);
  }
  return result;
}

ViyAbiInputPlan viy_plan_abi_input(const ViyAbiLayout &layout,
                                   const EmuInput &input,
                                   uint64_t entry_sp,
                                   uint64_t stack_base,
                                   uint64_t stack_size,
                                   bool big_endian)
{
  ViyAbiInputPlan result;
  if ( !layout.supported() || (layout.pointer_size != 4 && layout.pointer_size != 8) )
  {
    result.error = ViyAbiPlanError::UNSUPPORTED_ABI;
    return result;
  }
  if ( input.stack_arg_offset != 0
    && input.stack_arg_offset != layout.stack_argument_offset )
  {
    result.error = ViyAbiPlanError::STACK_OFFSET_MISMATCH;
    return result;
  }

  size_t positional = 0;
  for ( ; positional < input.args.size()
       && positional < layout.argument_registers.size(); ++positional )
    result.registers.push_back(
        { layout.argument_registers[positional], input.args[positional] });

  for ( const EmuInput::ArgOverride &argument : input.arg_overrides )
    if ( argument.index < layout.argument_registers.size() )
      result.registers.push_back(
          { layout.argument_registers[argument.index], argument.value });
  for ( const EmuInput::RegisterOverride &reg : input.register_overrides )
  {
    if ( reg.reg < 0 )
    {
      result.error = ViyAbiPlanError::INVALID_REGISTER;
      return result;
    }
    result.registers.push_back({ reg.reg, reg.value });
  }

  std::vector<uint64_t> stack_values;
  stack_values.insert(stack_values.end(),
                      input.args.begin() + static_cast<std::ptrdiff_t>(positional),
                      input.args.end());
  stack_values.insert(stack_values.end(), input.stack_args.begin(), input.stack_args.end());

  uint64_t stack_end = 0;
  uint64_t destination = entry_sp;
  const uint64_t return_slot = layout.return_address_on_stack
                             ? layout.pointer_size : 0;
  if ( !checked_add(stack_base, stack_size, &stack_end)
    || !checked_add(destination, return_slot, &destination)
    || !checked_add(destination, layout.stack_argument_offset, &destination) )
  {
    result.error = ViyAbiPlanError::ADDRESS_OVERFLOW;
    return result;
  }

  for ( uint64_t value : stack_values )
  {
    uint64_t next = 0;
    if ( destination < stack_base
      || !checked_add(destination, layout.pointer_size, &next)
      || next > stack_end )
    {
      result.error = ViyAbiPlanError::STACK_OUT_OF_RANGE;
      result.registers.clear();
      result.stack.clear();
      return result;
    }
    ViyAbiStackWrite write;
    write.address = destination;
    write.size = layout.pointer_size;
    for ( size_t byte = 0; byte < layout.pointer_size; ++byte )
    {
      const size_t shift_index = big_endian
                               ? size_t(layout.pointer_size) - 1 - byte : byte;
      write.bytes[byte] = uint8_t(value >> (8 * shift_index));
    }
    result.stack.push_back(write);
    destination = next;
  }
  return result;
}

} // namespace viy
