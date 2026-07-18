#include "smir_analysis.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <vector>

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

using namespace analysis;

decltype(&rax_analyze) g_real_analyze = nullptr;

rax_status truncating_analyze(int arch, uint32_t mode, uint64_t pc,
                              const void *bytes, size_t length,
                              rax_analysis *summary,
                              rax_analysis_effect *effects, size_t capacity,
                              size_t *required)
{
  if ( g_real_analyze == nullptr )
    return RAX_ERR_INTERNAL;
  if ( effects != nullptr && capacity != 0 )
    return g_real_analyze(arch, mode, pc, bytes, length, summary, effects,
                          0, required);
  return g_real_analyze(arch, mode, pc, bytes, length, summary, effects,
                        capacity, required);
}

ProgramImage image_with_code(ViyArch arch)
{
  ProgramImage image;
  image.arch = arch;
  image.lo = 0x1000;
  image.hi = 0x3000;
  image.generation = 7;
  SegImage segment;
  segment.start = image.lo;
  segment.end = image.hi;
  segment.perm = uint32_t(ViySegPerm::READ) | uint32_t(ViySegPerm::EXEC);
  segment.bitness = arch == ViyArch::X86_32 ? 1 : 2;
  segment.bytes.assign(size_t(segment.end - segment.start), 0x90);
  segment.mask.assign((segment.bytes.size() + 7u) / 8u, 0xff);
  image.segs.push_back(std::move(segment));
  return image;
}

void put(ProgramImage &image, uint64_t ea, std::initializer_list<uint8_t> bytes)
{
  SegImage &segment = image.segs.front();
  CHECK(segment.contains(ea));
  CHECK(bytes.size() <= size_t(segment.end - ea));
  std::copy(bytes.begin(), bytes.end(),
            segment.bytes.begin() + std::ptrdiff_t(ea - segment.start));
}

const rax_analysis_effect *find_effect(const SmirInstructionAnalysis &result,
                                       uint16_t kind, uint32_t access,
                                       int reg = -1)
{
  for ( const rax_analysis_effect &effect : result.effects )
    if ( effect.kind == kind
      && (effect.access & access) == access
      && (reg < 0 || effect.reg == reg) )
      return &effect;
  return nullptr;
}

void require_real_rax(const RaxApi *api)
{
  if ( api != nullptr && api->analyze != nullptr )
    return;
  if ( const char *required = std::getenv("VIY_REQUIRE_RAX_TESTS");
       required != nullptr && required[0] == '1' )
  {
    std::cerr << "required rax 1.3 analyzer unavailable: "
              << rax_unavailable_reason() << '\n';
    std::exit(2);
  }
  std::cout << "SKIP: compatible linked rax_analyze not available\n";
  std::exit(77);
}

} // namespace
} // namespace viy

int main()
{
  using namespace viy;
  using namespace viy::analysis;

  const RaxApi *api = rax_load();
  require_real_rax(api);
  CHECK(api != nullptr && api->analyze != nullptr);

  ProgramImage image = image_with_code(ViyArch::X86_64);
  put(image, 0x1000, { 0x48, 0xc7, 0xc0, 0x34, 0x12, 0x00, 0x00 });
  // mov rax, qword ptr [0x2000] (SIB with no base)
  put(image, 0x1040, { 0x48, 0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00 });
  // mov rax, [rip+0xf79] => 0x1087 + 0xf79 == 0x2000
  put(image, 0x1080, { 0x48, 0x8b, 0x05, 0x79, 0x0f, 0x00, 0x00 });
  // call 0x2000 => next 0x10c5 + 0xf3b
  put(image, 0x10c0, { 0xe8, 0x3b, 0x0f, 0x00, 0x00 });

  FuncRange function;
  function.start = 0x1000;
  function.end = 0x1100;
  function.chunks.push_back({ function.start, function.end });
  function.generation = image.generation;
  EvidenceStore store;

  SmirInstructionAnalysis constant;
  CHECK(viy_analyze_instruction_effects(api, image, 0x1000, 0, constant));
  CHECK((constant.summary.flags & RAX_ANALYSIS_COMPLETE) != 0);
  const rax_analysis_effect *write = find_effect(
      constant, RAX_EFFECT_REGISTER, RAX_EFFECT_WRITE, RAX_X86_REG_RAX);
  CHECK(write != nullptr);
  CHECK(write->value_kind == RAX_VALUE_CONSTANT && write->value == 0x1234);
  SmirAnalysisStats constant_stats =
      viy_record_smir_analysis(constant, function, store);
  CHECK(constant_stats.register_constant_facts == 1);

  SmirInstructionAnalysis absolute;
  CHECK(viy_analyze_instruction_effects(api, image, 0x1040, 0, absolute));
  const rax_analysis_effect *absolute_read =
      find_effect(absolute, RAX_EFFECT_MEMORY, RAX_EFFECT_READ);
  CHECK(absolute_read != nullptr);
  CHECK(absolute_read->address_kind == RAX_ADDRESS_ABSOLUTE);
  CHECK(absolute_read->address == 0x2000);
  CHECK(viy_record_smir_analysis(absolute, function, store).memory_access_facts == 1);

  SmirInstructionAnalysis relative;
  CHECK(viy_analyze_instruction_effects(api, image, 0x1080, 0, relative));
  const rax_analysis_effect *relative_read =
      find_effect(relative, RAX_EFFECT_MEMORY, RAX_EFFECT_READ);
  CHECK(relative_read != nullptr);
  CHECK(relative_read->address_kind == RAX_ADDRESS_PC_RELATIVE);
  CHECK(relative_read->address == 0x2000);
  CHECK(viy_record_smir_analysis(relative, function, store).memory_access_facts == 1);

  SmirInstructionAnalysis direct;
  CHECK(viy_analyze_instruction_effects(api, image, 0x10c0, 0, direct));
  CHECK(direct.summary.decoded.flow == RAX_FLOW_CALL);
  CHECK(direct.summary.decoded.has_target != 0);
  CHECK(direct.summary.decoded.target == 0x2000);
  CHECK(viy_record_smir_analysis(direct, function, store).code_target_facts == 1);

  bool saw_constant = false;
  bool saw_absolute_memory = false;
  bool saw_target = false;
  for ( const EvidenceRecord &record : store.records() )
  {
    if ( const auto *value = std::get_if<RegisterValueFact>(&record.payload) )
      saw_constant = value->instruction == 0x1000
                  && value->register_id == "x86:rax"
                  && value->bytes.size() == 8
                  && value->bytes[0] == 0x34 && value->bytes[1] == 0x12;
    if ( const auto *memory = std::get_if<MemoryAccessFact>(&record.payload) )
      saw_absolute_memory = saw_absolute_memory
                         || (memory->address == 0x2000 && memory->size == 8
                          && memory->kind == MemoryAccessKind::Read);
    if ( const auto *target = std::get_if<CodeTargetFact>(&record.payload) )
      saw_target = target->from == 0x10c0 && target->target == 0x2000
                && target->kind == CodeTargetKind::Call && target->unique;
  }
  CHECK(saw_constant && saw_absolute_memory && saw_target);

  // Old x86 modes still decode, but rich SMIR effects explicitly degrade.
  ProgramImage old_mode = image_with_code(ViyArch::X86_32);
  put(old_mode, 0x1000, { 0x90 });
  SmirInstructionAnalysis unsupported;
  CHECK(viy_analyze_instruction_effects(api, old_mode, 0x1000, 0, unsupported));
  CHECK((unsupported.summary.flags & RAX_ANALYSIS_VALID) != 0);
  CHECK((unsupported.summary.flags & RAX_ANALYSIS_UNSUPPORTED) != 0);
  CHECK((unsupported.summary.flags & RAX_ANALYSIS_PARTIAL) != 0);
  CHECK(unsupported.effects.empty());

  // The raw ABI returns the full required count and a deterministic prefix on
  // truncation. The viy wrapper accepts only coherent negotiation metadata and
  // a complete, non-truncated final result.
  size_t required = 0;
  rax_analysis raw{};
  CHECK(api->analyze(RAX_ARCH_X86, RAX_MODE_64, 0x1000,
                      image.segs[0].bytes.data(), 16, &raw, nullptr, 0,
                      &required) == RAX_OK);
  CHECK(required != 0);
  std::vector<rax_analysis_effect> short_buffer(required);
  size_t reported = 0;
  CHECK(api->analyze(RAX_ARCH_X86, RAX_MODE_64, 0x1000,
                      image.segs[0].bytes.data(), 16, &raw,
                      short_buffer.data(), required - 1u,
                      &reported) == RAX_ERR_BOUNDS);
  CHECK(reported == required);
  CHECK((raw.flags & RAX_ANALYSIS_TRUNCATED) != 0);
  CHECK(raw.effect_count == required - 1u);

  RaxApi truncating = *api;
  g_real_analyze = api->analyze;
  truncating.analyze = &truncating_analyze;
  SmirInstructionAnalysis rejected;
  CHECK(!viy_analyze_instruction_effects(
      &truncating, image, 0x1000, 0, rejected));

  std::cout << "smir analysis consumer: OK\n";
  return 0;
}
