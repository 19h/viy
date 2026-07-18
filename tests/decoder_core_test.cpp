#include "decoder_core.hpp"
#include "rax_loader.hpp"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>

#define CHECK(condition)                                                     \
  do                                                                         \
  {                                                                          \
    if ( !(condition) )                                                      \
    {                                                                        \
      std::cerr << "CHECK failed: " #condition " at " << __FILE__ << ':'     \
                << __LINE__ << '\n';                                         \
      std::exit(1);                                                          \
    }                                                                        \
  } while ( false )

namespace viy {
namespace {

rax_decoded g_fake_decoded{};
rax_status g_fake_status = RAX_OK;

rax_status fake_decode(int, uint32_t, uint64_t, const void *, size_t,
                       rax_decoded *out)
{
  if ( out == nullptr )
    return RAX_ERR_ARG;
  *out = g_fake_decoded;
  return g_fake_status;
}

rax_decoded decoded(uint32_t size, int32_t flow, bool indirect = false,
                    bool has_target = false, uint64_t target = 0)
{
  rax_decoded result{};
  result.size = size;
  result.flow = flow;
  result.is_indirect = indirect ? 1u : 0u;
  result.has_target = has_target ? 1u : 0u;
  result.target = target;
  result.valid = 1;
  return result;
}

DecoderInstruction instruction(uint32_t size, int32_t flow,
                               bool indirect = false,
                               bool has_target = false,
                               uint64_t target = 0)
{
  DecoderInstruction result;
  result.valid = true;
  result.size = size;
  result.flow = flow;
  result.indirect = indirect;
  result.has_target = has_target;
  result.target = target;
  return result;
}

void test_architecture_and_mode_policy()
{
  uint32_t mode = 0;
  const DecoderArchitecture x64 =
      viy_decoder_architecture(ViyArch::X86_64, false);
  CHECK(x64.valid && x64.rax_arch == RAX_ARCH_X86);
  CHECK(!x64.per_instruction_thumb);
  CHECK(viy_decoder_mode(x64, DecoderArmState::Unknown, mode));
  CHECK(mode == RAX_MODE_64);

  const DecoderArchitecture arm =
      viy_decoder_architecture(ViyArch::ARM32, false);
  CHECK(arm.valid && arm.rax_arch == RAX_ARCH_ARM);
  CHECK(arm.per_instruction_thumb);
  CHECK(!viy_decoder_mode(arm, DecoderArmState::Unknown, mode));
  CHECK(mode == 0);
  CHECK(viy_decoder_mode(arm, DecoderArmState::Arm, mode));
  CHECK(mode == (RAX_MODE_LITTLE_ENDIAN | RAX_MODE_ARM));
  CHECK(viy_decoder_mode(arm, DecoderArmState::Thumb, mode));
  CHECK(mode == (RAX_MODE_LITTLE_ENDIAN | RAX_MODE_THUMB));

  const DecoderArchitecture arm_be =
      viy_decoder_architecture(ViyArch::ARM32, true);
  CHECK(viy_decoder_mode(arm_be, DecoderArmState::Thumb, mode));
  CHECK(mode == (RAX_MODE_BIG_ENDIAN | RAX_MODE_THUMB));

  const DecoderArchitecture cortex =
      viy_decoder_architecture(ViyArch::CORTEX_M, false);
  CHECK(cortex.valid && !cortex.per_instruction_thumb);
  CHECK(viy_decoder_mode(cortex, DecoderArmState::Unknown, mode));
  CHECK(mode == (RAX_MODE_LITTLE_ENDIAN | RAX_MODE_THUMB));

  const DecoderArchitecture unsupported =
      viy_decoder_architecture(ViyArch::UNSUPPORTED, false);
  CHECK(!unsupported.valid);
  CHECK(!viy_decoder_mode(unsupported, DecoderArmState::Arm, mode));
  CHECK(mode == 0);
}

void test_chunk_windows()
{
  CHECK(viy_decoder_window_size(0x1000, 0x1010, 16) == 16);
  CHECK(viy_decoder_window_size(0x100f, 0x1010, 16) == 1);
  CHECK(viy_decoder_window_size(0x1010, 0x1010, 16) == 0);
  CHECK(viy_decoder_window_size(0x1011, 0x1010, 16) == 0);
  CHECK(viy_decoder_window_size(0x1000, 0x2000, 0) == 0);
  CHECK(viy_decoder_window_size(
      std::numeric_limits<uint64_t>::max() - 1,
      std::numeric_limits<uint64_t>::max(), 16) == 1);

  // A five-byte decode at the final two bytes of a chunk must fail closed even
  // if adjacent mapped bytes would have completed it.
  g_fake_status = RAX_OK;
  g_fake_decoded = decoded(5, RAX_FLOW_CALL, false, true, 0x2000);
  const uint8_t adjacent_bytes[16] = {};
  const size_t chunk_bytes = viy_decoder_window_size(0x10fe, 0x1100, 16);
  CHECK(chunk_bytes == 2);
  const DecoderDecodeResult truncated = viy_decode_one(
      fake_decode, RAX_ARCH_X86, RAX_MODE_64, 0x10fe,
      adjacent_bytes, chunk_bytes);
  CHECK(truncated.status == DecoderDecodeStatus::MalformedResult);
  CHECK(!viy_decoder_direct_target(truncated.instruction).valid);
}

void test_fake_decode_validation()
{
  const uint8_t bytes[8] = {};
  CHECK(viy_decode_one(nullptr, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::Unavailable);
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, nullptr, sizeof(bytes)).status
        == DecoderDecodeStatus::InvalidInput);
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, 0).status
        == DecoderDecodeStatus::InvalidInput);

  g_fake_status = RAX_ERR_ARCH;
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::BackendError);

  g_fake_status = RAX_OK;
  g_fake_decoded = {};
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::InvalidEncoding);

  g_fake_decoded = decoded(1, RAX_FLOW_FALLTHROUGH);
  DecoderDecodeResult result = viy_decode_one(
      fake_decode, RAX_ARCH_X86, RAX_MODE_64, 0x1000, bytes, sizeof(bytes));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  CHECK(result.instruction.size == 1);
  CHECK(!viy_decoder_direct_target(result.instruction).valid);

  g_fake_decoded = decoded(5, RAX_FLOW_CALL, false, true, 0x12345678);
  result = viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                          0x1000, bytes, sizeof(bytes));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  DecoderDirectTarget target = viy_decoder_direct_target(result.instruction);
  CHECK(target.valid && target.kind == DecoderTargetKind::Call);
  CHECK(target.address == 0x12345678);

  g_fake_decoded = decoded(2, RAX_FLOW_COND_BRANCH, false, true, 0);
  result = viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                          0x1000, bytes, sizeof(bytes));
  target = viy_decoder_direct_target(result.instruction);
  CHECK(result.status == DecoderDecodeStatus::Valid);
  CHECK(target.valid && target.kind == DecoderTargetKind::Jump);
  CHECK(target.address == 0); // address zero is a valid encoded target

  g_fake_decoded = decoded(2, RAX_FLOW_CALL); // direct flow without target
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::MalformedResult);
  g_fake_decoded = decoded(2, RAX_FLOW_INDIRECT_JUMP, true, true, 0x2000);
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::MalformedResult);
  g_fake_decoded = decoded(2, RAX_FLOW_FALLTHROUGH, true);
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::MalformedResult);
  g_fake_decoded = decoded(1, 999);
  CHECK(viy_decode_one(fake_decode, RAX_ARCH_X86, RAX_MODE_64,
                       0x1000, bytes, sizeof(bytes)).status
        == DecoderDecodeStatus::MalformedResult);
}

void test_comparison_policy()
{
  const DecoderInstruction call =
      instruction(5, RAX_FLOW_CALL, false, true, 0x2000);
  DecoderComparison comparison = viy_compare_decoders(call, call);
  CHECK(comparison.comparable);
  CHECK(!comparison.size_disagreement);
  CHECK(!comparison.flow_disagreement);
  CHECK(comparison.targets_comparable);
  CHECK(!comparison.target_disagreement);

  const DecoderInstruction wrong_size =
      instruction(6, RAX_FLOW_CALL, false, true, 0x2000);
  comparison = viy_compare_decoders(call, wrong_size);
  CHECK(comparison.size_disagreement);
  CHECK(!comparison.flow_disagreement);
  CHECK(!comparison.target_disagreement);

  const DecoderInstruction jump =
      instruction(5, RAX_FLOW_BRANCH, false, true, 0x2000);
  comparison = viy_compare_decoders(call, jump);
  CHECK(comparison.flow_disagreement);
  CHECK(comparison.target_disagreement); // same address, different target kind

  const DecoderInstruction wrong_target =
      instruction(5, RAX_FLOW_CALL, false, true, 0x3000);
  comparison = viy_compare_decoders(call, wrong_target);
  CHECK(!comparison.flow_disagreement);
  CHECK(comparison.target_disagreement);

  DecoderInstruction invalid = call;
  invalid.valid = false;
  comparison = viy_compare_decoders(call, invalid);
  CHECK(!comparison.comparable);
  CHECK(!comparison.size_disagreement && !comparison.flow_disagreement);
}

void require_real_decoder(const RaxApi *api)
{
  if ( api != nullptr && api->decode != nullptr )
    return;
  if ( const char *required = std::getenv("VIY_REQUIRE_RAX_TESTS");
       required != nullptr && required[0] == '1' )
  {
    std::cerr << "required rax decoder unavailable: "
              << rax_unavailable_reason() << '\n';
    std::exit(2);
  }
  std::cout << "SKIP: compatible linked rax_decode not available\n";
  std::exit(77);
}

void test_real_rax_decode()
{
  const RaxApi *api = rax_load();
  require_real_decoder(api);
  CHECK(api != nullptr && api->decode != nullptr);

  const DecoderArchitecture architecture =
      viy_decoder_architecture(ViyArch::X86_64, false);
  uint32_t mode = 0;
  CHECK(viy_decoder_mode(architecture, DecoderArmState::Unknown, mode));

  const uint8_t nop[] = { 0x90 };
  DecoderDecodeResult result = viy_decode_one(
      api->decode, architecture.rax_arch, mode, 0x1000, nop, sizeof(nop));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  CHECK(result.instruction.size == 1);
  CHECK(result.instruction.flow == RAX_FLOW_FALLTHROUGH);

  const uint8_t call[] = { 0xe8, 0x05, 0x00, 0x00, 0x00 };
  result = viy_decode_one(api->decode, architecture.rax_arch, mode,
                          0x1000, call, sizeof(call));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  DecoderDirectTarget target = viy_decoder_direct_target(result.instruction);
  CHECK(target.valid && target.kind == DecoderTargetKind::Call);
  CHECK(target.address == 0x100a);
  const DecoderInstruction ida_call =
      instruction(5, RAX_FLOW_CALL, false, true, 0x100a);
  DecoderComparison comparison = viy_compare_decoders(ida_call,
                                                       result.instruction);
  CHECK(comparison.comparable);
  CHECK(!comparison.size_disagreement && !comparison.flow_disagreement);
  CHECK(!comparison.target_disagreement);
  comparison = viy_compare_decoders(
      instruction(4, RAX_FLOW_CALL, false, true, 0x100a), result.instruction);
  CHECK(comparison.size_disagreement);
  comparison = viy_compare_decoders(
      instruction(5, RAX_FLOW_BRANCH, false, true, 0x100a),
      result.instruction);
  CHECK(comparison.flow_disagreement && comparison.target_disagreement);
  comparison = viy_compare_decoders(
      instruction(5, RAX_FLOW_CALL, false, true, 0x100b), result.instruction);
  CHECK(!comparison.flow_disagreement && comparison.target_disagreement);

  const uint8_t jump[] = { 0xe9, 0x05, 0x00, 0x00, 0x00 };
  result = viy_decode_one(api->decode, architecture.rax_arch, mode,
                          0x2000, jump, sizeof(jump));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  target = viy_decoder_direct_target(result.instruction);
  CHECK(target.valid && target.kind == DecoderTargetKind::Jump);
  CHECK(target.address == 0x200a);

  const uint8_t conditional[] = { 0x75, 0x05 };
  result = viy_decode_one(api->decode, architecture.rax_arch, mode,
                          0x3000, conditional, sizeof(conditional));
  CHECK(result.status == DecoderDecodeStatus::Valid);
  CHECK(result.instruction.flow == RAX_FLOW_COND_BRANCH);
  target = viy_decoder_direct_target(result.instruction);
  CHECK(target.valid && target.kind == DecoderTargetKind::Jump);
  CHECK(target.address == 0x3007);

  const uint8_t truncated_call[] = { 0xe8, 0x00 };
  result = viy_decode_one(api->decode, architecture.rax_arch, mode,
                          0x4000, truncated_call, sizeof(truncated_call));
  CHECK(result.status != DecoderDecodeStatus::Valid);
  CHECK(!viy_decoder_direct_target(result.instruction).valid);
}

} // namespace
} // namespace viy

int main()
{
  viy::test_architecture_and_mode_policy();
  viy::test_chunk_windows();
  viy::test_fake_decode_validation();
  viy::test_comparison_policy();
  viy::test_real_rax_decode();
  std::cout << "decoder core tests passed\n";
  return 0;
}
