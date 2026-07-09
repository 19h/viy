#include "abi_policy.hpp"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <vector>

using namespace viy;

namespace {

int failures = 0;

#define CHECK(condition)                                                        \
  do                                                                            \
  {                                                                             \
    if ( !(condition) )                                                         \
    {                                                                           \
      ++failures;                                                               \
      std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << ": "            \
                << #condition << '\n';                                          \
    }                                                                           \
  } while ( false )

template <typename T>
void check_vector(const std::vector<T> &actual, const std::vector<T> &expected)
{
  CHECK(actual == expected);
}

uint64_t stack_scalar(const ViyAbiStackWrite &write, bool big_endian)
{
  uint64_t result = 0;
  for ( size_t index = 0; index < write.size; ++index )
  {
    const size_t shift = big_endian ? size_t(write.size) - 1 - index : index;
    result |= uint64_t(write.bytes[index]) << (8 * shift);
  }
  return result;
}

void check_layouts()
{
  CHECK(viy_abi_for_arch(ViyArch::X86_16) == ViyAbi::UNKNOWN);
  CHECK(viy_abi_for_arch(ViyArch::X86_32) == ViyAbi::X86_32);
  CHECK(viy_abi_for_arch(ViyArch::X86_64, false) == ViyAbi::X86_64_SYSV);
  CHECK(viy_abi_for_arch(ViyArch::X86_64, true) == ViyAbi::X86_64_WIN64);
  CHECK(viy_abi_for_arch(ViyArch::ARM32) == ViyAbi::AAPCS32);
  CHECK(viy_abi_for_arch(ViyArch::ARM64) == ViyAbi::AAPCS64);
  CHECK(viy_abi_for_arch(ViyArch::RISCV64) == ViyAbi::RISCV64);
  CHECK(viy_abi_for_arch(ViyArch::CORTEX_M) == ViyAbi::CORTEX_M);
  CHECK(viy_abi_for_arch(ViyArch::HEXAGON) == ViyAbi::HEXAGON);

  const ViyAbiLayout &i386 = viy_abi_layout(ViyAbi::X86_32);
  CHECK(i386.pointer_size == 4);
  CHECK(i386.return_address_on_stack);
  CHECK(i386.argument_registers.empty());

  const ViyAbiLayout &sysv = viy_abi_layout(ViyAbi::X86_64_SYSV);
  CHECK(sysv.pointer_size == 8 && sysv.return_address_on_stack);
  CHECK(sysv.stack_argument_offset == 0);
  check_vector(sysv.argument_registers,
               { RAX_X86_REG_RDI, RAX_X86_REG_RSI, RAX_X86_REG_RDX,
                 RAX_X86_REG_RCX, RAX_X86_REG_R8, RAX_X86_REG_R9 });

  const ViyAbiLayout &win = viy_abi_layout(ViyAbi::X86_64_WIN64);
  CHECK(win.pointer_size == 8 && win.return_address_on_stack);
  CHECK(win.stack_argument_offset == 32);
  check_vector(win.argument_registers,
               { RAX_X86_REG_RCX, RAX_X86_REG_RDX,
                 RAX_X86_REG_R8, RAX_X86_REG_R9 });

  const ViyAbiLayout &arm32 = viy_abi_layout(ViyAbi::AAPCS32);
  CHECK(arm32.pointer_size == 4 && !arm32.return_address_on_stack);
  check_vector(arm32.argument_registers,
               { RAX_ARM_R(0), RAX_ARM_R(1), RAX_ARM_R(2), RAX_ARM_R(3) });

  const ViyAbiLayout &arm64 = viy_abi_layout(ViyAbi::AAPCS64);
  CHECK(arm64.pointer_size == 8 && !arm64.return_address_on_stack);
  check_vector(arm64.argument_registers,
               { RAX_ARM64_X(0), RAX_ARM64_X(1), RAX_ARM64_X(2), RAX_ARM64_X(3),
                 RAX_ARM64_X(4), RAX_ARM64_X(5), RAX_ARM64_X(6), RAX_ARM64_X(7) });

  const ViyAbiLayout &rv = viy_abi_layout(ViyAbi::RISCV64);
  CHECK(rv.pointer_size == 8 && !rv.return_address_on_stack);
  check_vector(rv.argument_registers,
               { RAX_RISCV_X(10), RAX_RISCV_X(11), RAX_RISCV_X(12), RAX_RISCV_X(13),
                 RAX_RISCV_X(14), RAX_RISCV_X(15), RAX_RISCV_X(16), RAX_RISCV_X(17) });

  const ViyAbiLayout &cm = viy_abi_layout(ViyAbi::CORTEX_M);
  CHECK(cm.pointer_size == 4 && !cm.return_address_on_stack);
  check_vector(cm.argument_registers,
               { RAX_CM_R(0), RAX_CM_R(1), RAX_CM_R(2), RAX_CM_R(3) });

  const ViyAbiLayout &hex = viy_abi_layout(ViyAbi::HEXAGON);
  CHECK(hex.pointer_size == 4 && !hex.return_address_on_stack);
  check_vector(hex.argument_registers,
               { RAX_HEX_R(0), RAX_HEX_R(1), RAX_HEX_R(2),
                 RAX_HEX_R(3), RAX_HEX_R(4), RAX_HEX_R(5) });
}

void check_plan(ViyAbi abi, size_t register_count, uint64_t first_stack_address,
                bool big_endian = false)
{
  const ViyAbiLayout &layout = viy_abi_layout(abi);
  EmuInput input;
  for ( size_t index = 0; index < register_count + 2; ++index )
    input.args.push_back(0x1111000000000000ull + uint64_t(index));
  constexpr uint64_t stack_base = 0x70000000;
  constexpr uint64_t stack_size = 0x10000;
  constexpr uint64_t sp = stack_base + 0x8000;
  const ViyAbiInputPlan plan = viy_plan_abi_input(
      layout, input, sp, stack_base, stack_size, big_endian);
  CHECK(plan.valid());
  CHECK(plan.registers.size() == register_count);
  CHECK(plan.stack.size() == 2);
  if ( plan.registers.size() == register_count )
  {
    for ( size_t index = 0; index < register_count; ++index )
    {
      CHECK(plan.registers[index].reg == layout.argument_registers[index]);
      CHECK(plan.registers[index].value == input.args[index]);
    }
  }
  if ( plan.stack.size() == 2 )
  {
    const uint64_t mask = layout.pointer_size == 4 ? 0xFFFFFFFFull
                                                   : std::numeric_limits<uint64_t>::max();
    CHECK(plan.stack[0].address == first_stack_address);
    CHECK(plan.stack[1].address == first_stack_address + layout.pointer_size);
    CHECK(stack_scalar(plan.stack[0], big_endian) == (input.args[register_count] & mask));
    CHECK(stack_scalar(plan.stack[1], big_endian) == (input.args[register_count + 1] & mask));
  }
}

void check_placements()
{
  constexpr uint64_t sp = 0x70008000;
  check_plan(ViyAbi::X86_64_SYSV, 6, sp + 8);
  // The direct input leaves stack_arg_offset zero: the production ABI layout
  // must still place the fifth Win64 argument after return+32-byte home area.
  check_plan(ViyAbi::X86_64_WIN64, 4, sp + 8 + 32);
  check_plan(ViyAbi::X86_32, 0, sp + 4);
  check_plan(ViyAbi::AAPCS32, 4, sp, true);
  check_plan(ViyAbi::AAPCS64, 8, sp);
  check_plan(ViyAbi::RISCV64, 8, sp);
  check_plan(ViyAbi::CORTEX_M, 4, sp);
  check_plan(ViyAbi::HEXAGON, 6, sp);

  EmuInput custom;
  custom.args = { 0x10, 0x20 };
  custom.arg_overrides.push_back({ 0, 0x30 }); // positional override is later
  custom.register_overrides.push_back({ RAX_X86_REG_ECX, 0x12345678 });
  custom.register_overrides.push_back({ RAX_X86_REG_EDX, 0x87654321 });
  const ViyAbiInputPlan custom_plan = viy_plan_abi_input(
      viy_abi_layout(ViyAbi::X86_32), custom, sp,
      0x70000000, 0x10000, false);
  CHECK(custom_plan.valid());
  CHECK(custom_plan.registers.size() == 2);
  CHECK(custom_plan.registers[0].reg == RAX_X86_REG_ECX
     && custom_plan.registers[0].value == 0x12345678);
  CHECK(custom_plan.registers[1].reg == RAX_X86_REG_EDX
     && custom_plan.registers[1].value == 0x87654321);
  CHECK(custom_plan.stack.size() == 2);
  if ( custom_plan.stack.size() == 2 )
  {
    CHECK(custom_plan.stack[0].address == sp + 4);
    CHECK(stack_scalar(custom_plan.stack[0], false) == 0x10);
    CHECK(stack_scalar(custom_plan.stack[1], false) == 0x20);
  }

  EmuInput override;
  override.args = { 1 };
  override.arg_overrides.push_back({ 0, 2 });
  const ViyAbiInputPlan override_plan = viy_plan_abi_input(
      viy_abi_layout(ViyAbi::X86_64_SYSV), override, sp,
      0x70000000, 0x10000, false);
  CHECK(override_plan.valid() && override_plan.registers.size() == 2);
  if ( override_plan.registers.size() == 2 )
  {
    CHECK(override_plan.registers[0].value == 1);
    CHECK(override_plan.registers[1].value == 2);
  }

  EmuInput mismatch;
  mismatch.stack_arg_offset = 16;
  CHECK(viy_plan_abi_input(viy_abi_layout(ViyAbi::X86_64_WIN64), mismatch,
                           sp, 0x70000000, 0x10000, false).error
        == ViyAbiPlanError::STACK_OFFSET_MISMATCH);
  EmuInput invalid;
  invalid.register_overrides.push_back({ -1, 0 });
  CHECK(viy_plan_abi_input(viy_abi_layout(ViyAbi::X86_32), invalid,
                           sp, 0x70000000, 0x10000, false).error
        == ViyAbiPlanError::INVALID_REGISTER);
  EmuInput too_large;
  too_large.stack_args = { 1, 2 };
  CHECK(viy_plan_abi_input(viy_abi_layout(ViyAbi::X86_32), too_large,
                           0x70000FF8, 0x70000000, 0x1000, false).error
        == ViyAbiPlanError::STACK_OUT_OF_RANGE);
}

void check_seed_corpus()
{
  constexpr uint64_t image = 0x100000;
  constexpr uint64_t stack = 0x70000000;
  constexpr uint64_t stack_size = 0x100000;
  for ( uint64_t seed : { 0ull, 1ull, 17ull,
                          std::numeric_limits<uint64_t>::max() } )
  {
    const std::vector<ViySeedValue> first =
        viy_seed_argument_corpus(seed, 24, image, stack, stack_size);
    const std::vector<ViySeedValue> second =
        viy_seed_argument_corpus(seed, 24, image, stack, stack_size);
    CHECK(first.size() == 24 && second.size() == first.size());
    for ( size_t index = 0; index < first.size(); ++index )
    {
      CHECK(first[index].kind == second[index].kind);
      CHECK(first[index].value == second[index].value);
      switch ( first[index].kind )
      {
        case ViySeedValueKind::ZERO: CHECK(first[index].value == 0); break;
        case ViySeedValueKind::ONE: CHECK(first[index].value == 1); break;
        case ViySeedValueKind::U16_MAX:
          CHECK(first[index].value == std::numeric_limits<uint16_t>::max()); break;
        case ViySeedValueKind::I16_MAX:
          CHECK(first[index].value == uint64_t(std::numeric_limits<int16_t>::max())); break;
        case ViySeedValueKind::I16_MIN:
          CHECK(first[index].value
                == uint64_t(int64_t(std::numeric_limits<int16_t>::min()))); break;
        case ViySeedValueKind::IMAGE_POINTER:
          CHECK(first[index].value == image); break;
        case ViySeedValueKind::STACK_POINTER:
          CHECK(first[index].value >= stack + stack_size / 2
             && first[index].value < stack + stack_size); break;
        case ViySeedValueKind::MIXED: break;
      }
    }
    for ( size_t group = 0; group < 3; ++group )
    {
      std::set<ViySeedValueKind> kinds;
      for ( size_t index = group * 8; index < group * 8 + 8; ++index )
        kinds.insert(first[index].kind);
      CHECK(kinds.size() == 8);
    }
  }

  const auto seed_one = viy_seed_argument_corpus(1, 8, image, stack, stack_size);
  const auto seed_two = viy_seed_argument_corpus(2, 8, image, stack, stack_size);
  bool differs = false;
  for ( size_t index = 0; index < seed_one.size(); ++index )
    differs = differs || seed_one[index].kind != seed_two[index].kind
                      || seed_one[index].value != seed_two[index].value;
  CHECK(differs);

  const auto large = viy_seed_argument_corpus(0, 100000, image, stack, 0x1000);
  for ( const ViySeedValue &item : large )
    if ( item.kind == ViySeedValueKind::STACK_POINTER )
      CHECK(item.value >= stack && item.value < stack + 0x1000);

  for ( const auto &invalid : {
          viy_seed_argument_corpus(0, 64, image, stack, 0),
          viy_seed_argument_corpus(0, 64, image,
                                   std::numeric_limits<uint64_t>::max() - 7, 16) } )
    CHECK(std::none_of(invalid.begin(), invalid.end(), [](const ViySeedValue &item)
      { return item.kind == ViySeedValueKind::STACK_POINTER; }));
}

} // namespace

int main()
{
  check_layouts();
  check_placements();
  check_seed_corpus();
  if ( failures != 0 )
  {
    std::cerr << failures << " ABI policy test(s) failed\n";
    return 1;
  }
  std::cout << "ABI policy tests passed\n";
  return 0;
}
