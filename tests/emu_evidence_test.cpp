#include "analysis_facts.hpp"
#include "emu_driver.hpp"
#include "evidence_bridge.hpp"
#include "evidence_store.hpp"
#include "rax_loader.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using namespace viy;
using namespace viy::analysis;

namespace {

int failures = 0;

void expect(bool condition, const std::string &message)
{
  if ( !condition )
  {
    ++failures;
    std::cerr << "FAIL: " << message << '\n';
  }
}

ProgramImage image(ViyArch arch = ViyArch::X86_64, bool big_endian = false)
{
  ProgramImage result;
  result.arch = arch;
  result.big_endian = big_endian;
  result.lo = 0x100000;
  result.hi = 0x104000;
  result.generation = 7;
  SegImage segment;
  segment.start = result.lo;
  segment.end = result.hi;
  segment.perm = 7;
  segment.bitness = arch == ViyArch::X86_64 ? 2 : 1;
  segment.bytes.resize(size_t(segment.end - segment.start), 0);
  segment.mask.resize((segment.bytes.size() + 7) / 8, 0xFF);
  result.segs.push_back(std::move(segment));
  return result;
}

void put(ProgramImage &img, uint64_t address, const std::vector<uint8_t> &bytes)
{
  SegImage &segment = img.segs.front();
  expect(address >= segment.start && address <= segment.end
      && bytes.size() <= segment.end - address,
         "test bytes fit in image");
  if ( address < segment.start || address > segment.end
    || bytes.size() > segment.end - address ) return;
  const size_t offset = size_t(address - segment.start);
  std::copy(bytes.begin(), bytes.end(), segment.bytes.begin() + std::ptrdiff_t(offset));
}

void put_in_segment(ProgramImage &img, uint64_t address,
                    const std::vector<uint8_t> &bytes)
{
  auto segment = std::find_if(img.segs.begin(), img.segs.end(),
    [&](const SegImage &candidate)
    {
      return address >= candidate.start && address <= candidate.end
          && bytes.size() <= candidate.end - address;
    });
  expect(segment != img.segs.end(), "test bytes fit in a mapped segment");
  if ( segment == img.segs.end() ) return;
  const size_t offset = size_t(address - segment->start);
  std::copy(bytes.begin(), bytes.end(),
            segment->bytes.begin() + std::ptrdiff_t(offset));
}

ProgramImage split_x64_image(uint32_t code_permissions)
{
  ProgramImage result;
  result.arch = ViyArch::X86_64;
  result.lo = 0x100000;
  result.hi = 0x103000;
  result.generation = 7;
  for ( const auto description : {
          std::pair<uint64_t, uint32_t>{0x100000, code_permissions},
          std::pair<uint64_t, uint32_t>{0x102000, 6u} } )
  {
    SegImage segment;
    segment.start = description.first;
    segment.end = segment.start + 0x1000;
    segment.perm = description.second;
    segment.bitness = 2;
    segment.bytes.resize(0x1000, 0);
    segment.mask.resize(0x200, 0xFF);
    result.segs.push_back(std::move(segment));
  }
  return result;
}

void u32(std::vector<uint8_t> &out, uint32_t value)
{
  for ( unsigned i = 0; i < 4; ++i ) out.push_back(uint8_t(value >> (i * 8)));
}

void u64(std::vector<uint8_t> &out, uint64_t value)
{
  for ( unsigned i = 0; i < 8; ++i ) out.push_back(uint8_t(value >> (i * 8)));
}

void mov_imm64(std::vector<uint8_t> &out, uint8_t opcode, uint64_t value)
{
  out.push_back(0x48); out.push_back(opcode); u64(out, value);
}

void call_rel32(std::vector<uint8_t> &out, uint64_t entry, uint64_t target)
{
  const uint64_t next = entry + out.size() + 5;
  const int64_t delta = int64_t(target) - int64_t(next);
  expect(delta >= std::numeric_limits<int32_t>::min()
      && delta <= std::numeric_limits<int32_t>::max(), "relative call fits");
  out.push_back(0xE8);
  u32(out, uint32_t(int32_t(delta)));
}

void store_rax(std::vector<uint8_t> &out, uint64_t address)
{
  out.push_back(0x48); out.push_back(0xA3); u64(out, address);
}

void load_rax(std::vector<uint8_t> &out, uint64_t address)
{
  out.push_back(0x48); out.push_back(0xA1); u64(out, address);
}

void store_rdi32_address(std::vector<uint8_t> &out, uint32_t address)
{
  out.insert(out.end(), {0x48, 0x89, 0x3C, 0x25});
  u32(out, address);
}

void store_byte32_address(std::vector<uint8_t> &out, uint32_t address,
                          uint8_t value)
{
  out.insert(out.end(), {0xC6, 0x04, 0x25});
  u32(out, address);
  out.push_back(value);
}

struct Run
{
  bool ran = false;
  EmuEvents events;
  EmuOutcome outcome;
};

Run run_x64(ProgramImage img, std::vector<uint8_t> code, uint64_t entry,
            uint64_t summary_address, EmuSummaryKind kind)
{
  put(img, entry, code);
  put(img, summary_address, {0xC3});
  FuncRange function;
  function.start = entry;
  function.end = entry + code.size();
  function.chunks.push_back(FuncChunk{function.start, function.end});
  function.generation = img.generation;
  img.entries.push_back(function);

  Run result;
  const RaxApi *api = rax_load();
  if ( api == nullptr ) return result;
  EmuDriver driver(api, img, true, false, {{summary_address, kind}});
  expect(driver.can_discover(), "real rax driver can discover");
  if ( !driver.can_discover() ) return result;
  ViyConfig config;
  config.max_insns = 10000;
  config.timeout_ms = 250;
  config.max_runtime_bytes = 1u << 20;
  config.want_drefs = true;
  config.want_runtime_strings = true;
  result.ran = driver.emulate_from(entry, function.end, config, result.events,
                                   &result.outcome, true, 17, 3);
  result.events.normalize();
  return result;
}

Run run_plain_x64(ProgramImage img, uint64_t entry, uint64_t end,
                  const ViyConfig &config, bool strict,
                  const RaxApi *api, const EmuInput *input = nullptr,
                  uint64_t seed = 0, uint32_t run_id = 0)
{
  FuncRange function;
  function.start = entry;
  function.end = end;
  function.chunks.push_back({entry, end});
  function.generation = img.generation;
  img.entries.push_back(function);
  Run result;
  EmuDriver driver(api, img, strict, false, {});
  expect(driver.can_discover(), "real rax plain driver can discover");
  if ( !driver.can_discover() ) return result;
  result.ran = driver.emulate_from(entry, end, config, result.events,
                                   &result.outcome, true, seed, run_id, input);
  result.events.normalize();
  return result;
}

std::optional<uint8_t> final_byte(const EmuEvents &events, uint64_t address)
{
  for ( const MemoryBytes &memory : events.final_writes )
    if ( address >= memory.addr && address - memory.addr < memory.bytes.size() )
      return memory.bytes[size_t(address - memory.addr)];
  return std::nullopt;
}

std::optional<uint64_t> final_u64(const EmuEvents &events, uint64_t address)
{
  uint64_t value = 0;
  for ( unsigned i = 0; i < 8; ++i )
  {
    const std::optional<uint8_t> byte = final_byte(events, address + i);
    if ( !byte.has_value() ) return std::nullopt;
    value |= uint64_t(*byte) << (i * 8);
  }
  return value;
}

std::optional<uint64_t> final_u64_for_run(const EmuEvents &events,
                                          uint64_t address,
                                          uint32_t run_id)
{
  for ( const MemoryBytes &memory : events.final_writes )
  {
    if ( memory.run_id != run_id || address < memory.addr
      || address - memory.addr > memory.bytes.size()
      || memory.bytes.size() - size_t(address - memory.addr) < 8 )
      continue;
    uint64_t result = 0;
    const size_t offset = size_t(address - memory.addr);
    for ( unsigned index = 0; index < 8; ++index )
      result |= uint64_t(memory.bytes[offset + index]) << (index * 8);
    return result;
  }
  return std::nullopt;
}

std::optional<uint32_t> final_u32(const EmuEvents &events, uint64_t address)
{
  uint32_t value = 0;
  for ( unsigned i = 0; i < 4; ++i )
  {
    const std::optional<uint8_t> byte = final_byte(events, address + i);
    if ( !byte.has_value() ) return std::nullopt;
    value |= uint32_t(*byte) << (i * 8);
  }
  return value;
}

std::vector<uint8_t> wrapper3(uint64_t entry, uint64_t target, uint64_t result,
                              uint64_t a0, uint64_t a1, uint64_t a2)
{
  std::vector<uint8_t> code;
  mov_imm64(code, 0xBF, a0); // rdi
  mov_imm64(code, 0xBE, a1); // rsi
  mov_imm64(code, 0xBA, a2); // rdx
  call_rel32(code, entry, target);
  store_rax(code, result);
  code.push_back(0xC3);
  return code;
}

void expect_success(const Run &run, const std::string &name)
{
  expect(run.ran, name + " emulation ran");
  expect(run.outcome.stop_valid, name + " has last-exit metadata");
  expect(run.outcome.returned, name + " returned to sentinel");
  expect(run.outcome.summarized_calls == 1, name + " modeled exactly one call");
  expect(run.outcome.instruction_count != 0, name + " records instruction count");
  expect(!run.events.execution.empty(), name + " records ordered execution points");
  expect(std::is_sorted(run.events.execution.begin(), run.events.execution.end(),
    [](const ExecPoint &a, const ExecPoint &b)
    {
      return std::tie(a.run_id, a.seed, a.sequence, a.pc)
           < std::tie(b.run_id, b.seed, b.sequence, b.pc);
    }), name + " execution points normalize in run/sequence order");
}

void test_real_summaries()
{
  if ( rax_load() == nullptr )
  {
    if ( std::getenv("VIY_REQUIRE_RAX_TESTS") != nullptr )
      expect(false, std::string("linked rax required: ") + rax_unavailable_reason());
    else
      std::cout << "SKIP: real summary tests (" << rax_unavailable_reason() << ")\n";
    return;
  }

  constexpr uint64_t entry = 0x100000;
  constexpr uint64_t target = 0x101000;
  constexpr uint64_t src = 0x102000;
  constexpr uint64_t dst = 0x102100;
  constexpr uint64_t result = 0x103000;

  {
    ProgramImage img = image();
    put(img, src, {'h','e','l','l','o',0});
    const Run run = run_x64(img, wrapper3(entry, target, result, dst, src, 6),
                            entry, target, EmuSummaryKind::MEMCPY);
    expect_success(run, "memcpy");
    for ( unsigned i = 0; i < 6; ++i )
      expect(final_byte(run.events, dst + i) == std::optional<uint8_t>(img.segs[0].bytes[size_t(src-img.lo+i)]),
             "memcpy copied byte " + std::to_string(i));
    expect(final_u64(run.events, result) == std::optional<uint64_t>(dst), "memcpy returns destination");
    expect(std::any_of(run.events.edges.begin(), run.events.edges.end(), [](const ExecEdge &edge)
      { return edge.kind == ExecEdge::Kind::Call; }), "decoder classifies summary edge as call");

    FuncRange function{entry, entry + wrapper3(entry, target, result, dst, src, 6).size(),
                       {{entry, entry + wrapper3(entry, target, result, dst, src, 6).size()}}, 0, 7};
    EvidenceStore store;
    const EvidenceBridgeStats bridge = viy_record_emulation_evidence(store, img, function,
                                                                      run.events, {});
    expect(bridge.rejected == 0, "memcpy events bridge without invalid facts");
    bool exact_value = false;
    bool call_observation = false;
    bool call_cfg_edge = false;
    for ( const EvidenceRecord &record : store.records() )
    {
      if ( const auto *fact = std::get_if<MemoryValueFact>(&record.payload) )
        if ( fact->address == dst )
          exact_value = fact->bytes == std::vector<uint8_t>({'h','e','l','l','o',0});
      if ( const auto *fact = std::get_if<CallObservationFact>(&record.payload) )
        call_observation = call_observation || fact->target == target;
      if ( const auto *fact = std::get_if<CfgCandidateFact>(&record.payload) )
        call_cfg_edge = call_cfg_edge
                     || (fact->to == target && fact->kind == CfgEdgeKind::Call
                      && fact->state == Reachability::Reached);
    }
    expect(exact_value, "summary access evidence carries copied bytes, not a zero placeholder");
    expect(call_observation, "classified dynamic calls publish call evidence");
    expect(call_cfg_edge, "classified dynamic calls publish CFG evidence");
  }

  {
    ProgramImage img = image();
    put(img, src, {'a','b','c','d','e','f','g','h','i','j'});
    const Run run = run_x64(img, wrapper3(entry, target, result, src + 2, src, 8),
                            entry, target, EmuSummaryKind::MEMMOVE);
    expect_success(run, "memmove");
    const std::vector<uint8_t> expected = {'a','b','c','d','e','f','g','h'};
    for ( size_t i = 0; i < expected.size(); ++i )
      expect(final_byte(run.events, src + 2 + i) == std::optional<uint8_t>(expected[i]),
             "memmove preserves overlap byte " + std::to_string(i));
  }

  {
    ProgramImage img = image();
    put(img, src, {'c','o','p','y',0});
    const Run run = run_x64(img, wrapper3(entry, target, result, dst, src, 0),
                            entry, target, EmuSummaryKind::STRCPY);
    expect_success(run, "strcpy");
    const std::vector<uint8_t> expected = {'c','o','p','y',0};
    for ( size_t i = 0; i < expected.size(); ++i )
      expect(final_byte(run.events, dst + i) == std::optional<uint8_t>(expected[i]),
             "strcpy output byte " + std::to_string(i));
  }

  {
    ProgramImage img = image();
    const Run run = run_x64(img, wrapper3(entry, target, result, dst, 0xA5, 19),
                            entry, target, EmuSummaryKind::MEMSET);
    expect_success(run, "memset");
    for ( unsigned i = 0; i < 19; ++i )
      expect(final_byte(run.events, dst + i) == std::optional<uint8_t>(0xA5),
             "memset wrote byte " + std::to_string(i));
  }

  {
    ProgramImage img = image();
    put(img, src, {'v','i','y',0});
    const Run run = run_x64(img, wrapper3(entry, target, result, src, 0, 0),
                            entry, target, EmuSummaryKind::STRLEN);
    expect_success(run, "strlen");
    expect(final_u64(run.events, result) == std::optional<uint64_t>(3), "strlen result is exact");
  }

  {
    ProgramImage img = image();
    put(img, src, {'a','b','c',0});
    put(img, dst, {'a','b','d',0});
    const Run run = run_x64(img, wrapper3(entry, target, result, src, dst, 0),
                            entry, target, EmuSummaryKind::STRCMP);
    expect_success(run, "strcmp");
    const std::optional<uint64_t> value = final_u64(run.events, result);
    expect(value.has_value() && int64_t(*value) < 0, "strcmp preserves negative ordering");
    const size_t reads = size_t(std::count_if(run.events.data.begin(), run.events.data.end(),
      [](const DataAcc &access) { return access.kind == RAX_MEM_READ; }));
    expect(reads >= 2, "strcmp records both input reads");
  }

  {
    ProgramImage img = image();
    put(img, src, {'x',0});
    put(img, dst, {0xCC,0xCC,0xCC,0xCC,0xCC});
    const Run run = run_x64(img, wrapper3(entry, target, result, dst, src, 5),
                            entry, target, EmuSummaryKind::STRNCPY);
    expect_success(run, "strncpy");
    const std::vector<uint8_t> expected = {'x',0,0,0,0};
    for ( size_t i = 0; i < expected.size(); ++i )
      expect(final_byte(run.events, dst + i) == std::optional<uint8_t>(expected[i]),
             "strncpy zero-pads byte " + std::to_string(i));
  }

  {
    ProgramImage img = image();
    const Run run = run_x64(img, wrapper3(entry, target, result, 32, 0, 0),
                            entry, target, EmuSummaryKind::ALLOCATE);
    expect_success(run, "malloc");
    const std::optional<uint64_t> pointer = final_u64(run.events, result);
    expect(pointer.has_value() && *pointer != 0 && (*pointer & 15) == 0,
           "malloc returns a non-null aligned scratch pointer");
  }

  {
    ProgramImage img = image();
    constexpr uint64_t result2 = result + 8;
    std::vector<uint8_t> code;
    mov_imm64(code, 0xBF, 16);
    call_rel32(code, entry, target);
    store_rax(code, result);
    mov_imm64(code, 0xBF, 32);
    call_rel32(code, entry, target);
    store_rax(code, result2);
    code.push_back(0xC3);
    const Run run = run_x64(img, code, entry, target, EmuSummaryKind::ALLOCATE);
    expect(run.ran && run.outcome.returned && run.outcome.summarized_calls == 2,
           "two malloc summaries resume and return");
    const std::optional<uint64_t> first = final_u64(run.events, result);
    const std::optional<uint64_t> second = final_u64(run.events, result2);
    expect(first.has_value() && second.has_value() && *second > *first
        && *second - *first == 16, "allocator returns deterministic non-overlapping objects");
  }

  {
    ProgramImage img = image();
    const Run run = run_x64(img, wrapper3(entry, target, result, 4, 8, 0),
                            entry, target, EmuSummaryKind::CALLOCATE);
    expect_success(run, "calloc");
    expect(std::any_of(run.events.data.begin(), run.events.data.end(), [](const DataAcc &access)
      { return access.scope == DataScope::HEAP && access.kind == RAX_MEM_WRITE && access.size == 32; }),
      "calloc records zero initialization in heap address space");
  }

  {
    ProgramImage img = image();
    const Run run = run_x64(img, wrapper3(entry, target, result,
                                           std::numeric_limits<uint64_t>::max(), 2, 0),
                            entry, target, EmuSummaryKind::CALLOCATE);
    expect_success(run, "overflowing calloc");
    expect(final_u64(run.events, result) == std::optional<uint64_t>(0),
           "overflowing calloc is modeled as allocation failure");
    expect(std::none_of(run.events.data.begin(), run.events.data.end(), [](const DataAcc &access)
      { return access.scope == DataScope::HEAP; }), "overflowing calloc writes no fabricated object");
  }

  {
    ProgramImage img = image();
    const Run run = run_x64(img, wrapper3(entry, target, result, 0xDEADBEEF, 0, 0),
                            entry, target, EmuSummaryKind::DEALLOCATE);
    expect_success(run, "free");
  }

  {
    ProgramImage img = image();
    std::vector<uint8_t> code;
    mov_imm64(code, 0xBF, 1);
    call_rel32(code, entry, target);
    // This store must be unreachable after a terminating summary.
    store_rax(code, result);
    code.push_back(0xC3);
    const Run run = run_x64(img, code, entry, target, EmuSummaryKind::TERMINATE);
    expect(run.ran, "exit emulation ran");
    expect(run.outcome.terminated_process && !run.outcome.returned,
           "exit is a definitive modeled process termination");
    expect(run.outcome.summarized_calls == 1, "exit summary counted once");
    expect(!final_u64(run.events, result).has_value(), "execution does not resume after exit");
  }

  {
    ProgramImage img = image();
    const uint64_t invalid = 0x444444440000ull;
    const Run run = run_x64(img, wrapper3(entry, target, result, dst, invalid, 8),
                            entry, target, EmuSummaryKind::MEMCPY);
    expect(run.ran && run.outcome.returned, "failed summary falls through to real stub");
    expect(run.outcome.summarized_calls == 0, "unreadable memcpy is not reported as modeled");
    for ( unsigned i = 0; i < 8; ++i )
      expect(!final_byte(run.events, dst + i).has_value(), "failed memcpy records no destination bytes");
  }


  // Exercise the stack-passed i386 ABI and the natural-width ESP/EBP/EAX IDs.
  {
    ProgramImage img = image(ViyArch::X86_32);
    put(img, src, {'i','3','8','6',0});
    std::vector<uint8_t> code;
    code.insert(code.end(), {0x6A, 0x05});                    // push 5
    code.push_back(0x68); u32(code, uint32_t(src));           // push src
    code.push_back(0x68); u32(code, uint32_t(dst));           // push dst
    call_rel32(code, entry, target);
    code.insert(code.end(), {0x83, 0xC4, 0x0C});              // add esp, 12
    code.push_back(0xA3); u32(code, uint32_t(result));         // mov [result], eax
    code.push_back(0xC3);
    put(img, entry, code);
    put(img, target, {0xC3});
    FuncRange function{entry, entry + code.size(), {{entry, entry + code.size()}}, 0, 7};
    img.entries.push_back(function);
    EmuDriver driver(rax_load(), img, true, false, {{target, EmuSummaryKind::MEMCPY}});
    ViyConfig config;
    config.max_insns = 10000; config.timeout_ms = 250; config.max_runtime_bytes = 1u << 20;
    EmuEvents events; EmuOutcome outcome;
    const bool ran = driver.emulate_from(entry, function.end, config, events, &outcome,
                                         false, 5, 4);
    events.normalize();
    expect(ran && outcome.returned && outcome.summarized_calls == 1,
           "i386 stack-argument summary returns successfully");
    expect(final_u32(events, result) == std::optional<uint32_t>(uint32_t(dst)),
           "i386 memcpy return uses EAX");
    expect(final_byte(events, dst) == std::optional<uint8_t>('i')
        && final_byte(events, dst + 4) == std::optional<uint8_t>(0),
        "i386 stack arguments are read at [esp+4]");
  }

  // Explicit/custom type information can seed raw architectural registers
  // (notably i386 fastcall ECX/EDX) without changing the stack ABI used by
  // modeled library calls.
  {
    ProgramImage img = image(ViyArch::X86_32);
    std::vector<uint8_t> code = {0x89, 0x0D}; // mov [disp32], ecx
    u32(code, uint32_t(result));
    code.push_back(0xC3);
    put(img, entry, code);
    FuncRange function{entry, entry + code.size(), {{entry, entry + code.size()}}, 0, 7};
    img.entries.push_back(function);
    EmuDriver driver(rax_load(), img, true, false, {});
    ViyConfig config;
    config.max_insns = 1000; config.timeout_ms = 250; config.max_runtime_bytes = 4096;
    EmuInput input;
    input.run_id = 9;
    input.register_overrides.push_back({RAX_X86_REG_ECX, 0x12345678});
    EmuEvents events; EmuOutcome outcome;
    const bool ran = driver.emulate_from(entry, function.end, config, events, &outcome,
                                         false, 0, 9, &input);
    events.normalize();
    expect(ran && outcome.returned, "i386 explicit register input runs to return");
    expect(final_u32(events, result) == std::optional<uint32_t>(0x12345678),
           "i386 explicit ECX override reaches guest state");
  }
}

void test_real_engine_policy()
{
  const RaxApi *api = rax_load();
  if ( api == nullptr )
  {
    if ( std::getenv("VIY_REQUIRE_RAX_TESTS") != nullptr )
      expect(false, std::string("linked rax required: ") + rax_unavailable_reason());
    else
      std::cout << "SKIP: real engine policy tests (" << rax_unavailable_reason() << ")\n";
    return;
  }

  constexpr uint64_t entry = 0x100000;
  constexpr uint64_t data = 0x102000;
  constexpr uint64_t result = 0x103000;
  ViyConfig config;
  config.max_insns = 1000;
  config.timeout_ms = 250;
  config.max_runtime_bytes = 1u << 20;
  config.want_drefs = true;
  config.want_runtime_strings = true;

  // One driver is reused for both runs. The second run must observe the
  // original image value, not the first run's write to `data` or `result`.
  {
    ProgramImage img = image();
    std::vector<uint8_t> initial;
    u64(initial, 0x1122334455667788ull);
    put(img, data, initial);
    put(img, result, std::vector<uint8_t>(8, 0));
    std::vector<uint8_t> code;
    load_rax(code, data);
    store_rax(code, result);
    store_rdi32_address(code, uint32_t(data));
    code.push_back(0xC3);
    put(img, entry, code);
    FuncRange function{entry, entry + code.size(),
                       {{entry, entry + code.size()}}, 0, 7};
    img.entries.push_back(function);
    EmuDriver driver(api, img, true, false, {});
    expect(driver.can_discover(), "isolation driver can discover");
    if ( driver.can_discover() )
    {
      EmuEvents events;
      EmuOutcome first_outcome, second_outcome;
      EmuInput first;
      first.seed = 101;
      first.run_id = 41;
      first.args = { 0xAAAAAAAAAAAAAAAAull };
      EmuInput second;
      second.seed = 202;
      second.run_id = 42;
      second.args = { 0xBBBBBBBBBBBBBBBBull };
      const bool ran_first = driver.emulate_from(
          entry, function.end, config, events, &first_outcome, true, 0, 0, &first);
      const bool ran_second = driver.emulate_from(
          entry, function.end, config, events, &second_outcome, true, 0, 0, &second);
      events.normalize();
      expect(ran_first && ran_second && first_outcome.returned && second_outcome.returned,
             "two isolated runs return using one engine");
      expect(final_u64_for_run(events, result, 41)
              == std::optional<uint64_t>(0x1122334455667788ull),
             "first run reads pristine image memory");
      expect(final_u64_for_run(events, result, 42)
              == std::optional<uint64_t>(0x1122334455667788ull),
             "second run restores memory before execution");
      expect(final_u64_for_run(events, data, 41)
              == std::optional<uint64_t>(0xAAAAAAAAAAAAAAAAull),
             "first isolated run records its own write");
      expect(final_u64_for_run(events, data, 42)
              == std::optional<uint64_t>(0xBBBBBBBBBBBBBBBBull),
             "second isolated run records its own write");
    }
  }

  // RX pages reject guest writes in strict mode, while compatibility mode is
  // intentionally RWX. This also validates that image loading precedes final
  // permission enforcement for non-writable code segments.
  {
    constexpr uint64_t rx_target = entry + 0x100;
    ProgramImage img = split_x64_image(5); // R|X
    std::vector<uint8_t> code;
    store_byte32_address(code, uint32_t(rx_target), 0xA5);
    code.push_back(0xC3);
    put_in_segment(img, entry, code);
    put_in_segment(img, rx_target, {0x11});
    const Run strict = run_plain_x64(img, entry, entry + code.size(),
                                     config, true, api);
    expect(strict.ran && strict.outcome.stop_valid && !strict.outcome.returned,
           "strict RX page denies guest write");
    expect(!final_byte(strict.events, rx_target).has_value(),
           "denied RX write produces no final-write evidence");
    const Run permissive = run_plain_x64(img, entry, entry + code.size(),
                                         config, false, api);
    expect(permissive.ran && permissive.outcome.returned,
           "permissive compatibility mode allows RX-page write");
    expect(final_byte(permissive.events, rx_target) == std::optional<uint8_t>(0xA5),
           "permissive RX write reaches guest memory");
  }

  // Conversely, an RW data page containing bytes is not executable in strict
  // mode. Compatibility mode demonstrates that the bytes themselves are valid.
  {
    ProgramImage img = split_x64_image(6); // R|W, no X
    const std::vector<uint8_t> code = {0xC3};
    put_in_segment(img, entry, code);
    const Run strict = run_plain_x64(img, entry, entry + code.size(),
                                     config, true, api);
    expect(strict.ran && strict.outcome.stop_valid && !strict.outcome.returned,
           "strict RW page denies instruction fetch");
    const Run permissive = run_plain_x64(img, entry, entry + code.size(),
                                         config, false, api);
    expect(permissive.ran && permissive.outcome.returned,
           "permissive compatibility mode executes the same RW bytes");
  }

  // A self-loop is terminated by the exact instruction budget, independently
  // of the much larger wall-clock cap.
  {
    ProgramImage img = image();
    const std::vector<uint8_t> code = {0xEB, 0xFE}; // jmp $
    put(img, entry, code);
    ViyConfig bounded = config;
    bounded.max_insns = 7;
    bounded.timeout_ms = 1000;
    const Run run = run_plain_x64(img, entry, entry + code.size(),
                                  bounded, true, api);
    expect(run.ran && run.outcome.stop_valid,
           "instruction-budget run reports a terminal reason");
    expect(run.outcome.stop_reason == RAX_STOP_COUNT,
           "instruction budget is classified as RAX_STOP_COUNT");
    expect(run.outcome.instruction_count == 7 && !run.outcome.returned,
           "instruction budget is enforced exactly");
  }

  // Static decode classifies taken jump and return edges. A cloned API with the
  // optional decode capability removed must still emit the observed edge with
  // Unknown kind instead of inventing a classification or losing the edge.
  {
    ProgramImage jump_image = image();
    const std::vector<uint8_t> jump = {0xEB, 0x02, 0x90, 0x90, 0xC3};
    put(jump_image, entry, jump);
    const Run classified = run_plain_x64(
        jump_image, entry, entry + jump.size(), config, true, api);
    expect(std::any_of(classified.events.edges.begin(), classified.events.edges.end(),
      [&](const ExecEdge &edge)
      {
        return edge.from == entry && edge.to == entry + 4
            && edge.kind == ExecEdge::Kind::Jump;
      }), "taken jump edge is decoder-classified");

    RaxApi without_decode = *api;
    without_decode.decode = nullptr;
    const Run fallback = run_plain_x64(
        jump_image, entry, entry + jump.size(), config, true, &without_decode);
    expect(std::any_of(fallback.events.edges.begin(), fallback.events.edges.end(),
      [&](const ExecEdge &edge)
      {
        return edge.from == entry && edge.to == entry + 4
            && edge.kind == ExecEdge::Kind::Unknown;
      }), "decode-unavailable edge falls back to Unknown");

    ProgramImage return_image = image();
    std::vector<uint8_t> via_return(17, 0x90);
    via_return[0] = 0x68; // push imm32
    const uint32_t target = uint32_t(entry + 16);
    for ( unsigned index = 0; index < 4; ++index )
      via_return[1 + index] = uint8_t(target >> (index * 8));
    via_return[5] = 0xC3;
    via_return[16] = 0xC3;
    put(return_image, entry, via_return);
    const Run returned = run_plain_x64(
        return_image, entry, entry + via_return.size(), config, true, api);
    expect(returned.outcome.returned, "return-edge fixture ultimately reaches sentinel");
    expect(std::any_of(returned.events.edges.begin(), returned.events.edges.end(),
      [&](const ExecEdge &edge)
      {
        return edge.from == entry + 5 && edge.to == entry + 16
            && edge.kind == ExecEdge::Kind::Return;
      }), "taken return edge is decoder-classified");
  }
}

void test_normalization()
{
  EmuEvents events;
  events.edges = {
    {2, 3, 7, 9, ExecEdge::Kind::Jump},
    {2, 3, 7, 9, ExecEdge::Kind::Jump},
    {1, 3, 7, 10, ExecEdge::Kind::Call},
    {2, 3, 7, 9, ExecEdge::Kind::Jump, 12},
  };
  events.execution = {
    {0x1002, 4, 5, 2},
    {0x1001, 1, 5, 1},
    {0x1001, 1, 5, 1},
    {0x1001, 3, 5, 1},
  };
  events.data = {
    {9, 0x2000, 2, 4, RAX_MEM_WRITE, DataScope::IMAGE, 0, 5, 2},
    {8, 0x1000, 1, 4, RAX_MEM_READ, DataScope::IMAGE, 0, 5, 1},
    {8, 0x1000, 1, 4, RAX_MEM_READ, DataScope::IMAGE, 0, 5, 1},
  };
  StatePoint state;
  state.source = 1; state.pc = 2; state.run_id = 5; state.seed = 1;
  state.regs = {{3, 4, 8}, {2, 3, 8}, {2, 3, 8}};
  events.states = {state, state};
  events.final_writes = {
    {0x1000, {2}, DataScope::IMAGE, 5, 1},
    {0x1000, {1}, DataScope::IMAGE, 5, 1},
    {0x1000, {1}, DataScope::IMAGE, 5, 1},
  };
  events.normalize();
  expect(events.edges.size() == 3,
         "normalization removes exact duplicate edges but preserves repetitions");
  expect(events.execution.size() == 3
      && events.execution[0].seed == 1 && events.execution[0].sequence == 1
      && events.execution[1].seed == 1 && events.execution[1].sequence == 3
      && events.execution[2].seed == 2,
         "ordered execution observations normalize canonically");
  expect(events.data.size() == 2 && events.data[0].seed == 1 && events.data[1].seed == 2,
         "memory order includes seed and removes exact merged access");
  expect(events.states.size() == 1 && events.states[0].regs.size() == 2
      && events.states[0].regs[0].reg == 2,
      "state registers and duplicate states normalize canonically");
  expect(events.final_writes.size() == 2 && events.final_writes[0].bytes == std::vector<uint8_t>{1},
         "final-write ordering includes bytes and is deterministic");

  const size_t edges = events.edges.size(), execution = events.execution.size();
  const size_t data = events.data.size();
  events.merge_from(events);
  events.normalize();
  expect(events.edges.size() == edges && events.execution.size() == execution
      && events.data.size() == data,
         "self-merge is defined and exact observations deduplicate");
}

void test_evidence_bridge()
{
  ProgramImage img = image(ViyArch::ARM64, true);
  FuncRange function;
  function.start = 0x100000;
  function.end = 0x100100;
  function.chunks = {{function.start, function.end}};
  function.generation = 7;

  EmuEvents events;
  events.edges.push_back({0x100010, 0x100080, 2, 3, ExecEdge::Kind::Call});
  events.data.push_back({0x100020, 0x102000, 0x11223344, 4, RAX_MEM_READ,
                         DataScope::IMAGE, 1, 2, 3});
  events.data.push_back({0x100020, 0x70000000, 1, 4, RAX_MEM_READ,
                         DataScope::STACK, 2, 2, 3});
  events.data.push_back({0x100020, 0x70010000, 2, 4, RAX_MEM_WRITE,
                         DataScope::HEAP, 3, 2, 3});
  // Same run id but another seed must not be selected as final-write support.
  events.data.push_back({0x100030, 0x102100, 0, 2, RAX_MEM_WRITE,
                         DataScope::IMAGE, 99, 2, 4});
  events.data.push_back({0x100040, 0x102100, 0, 2, RAX_MEM_WRITE,
                         DataScope::IMAGE, 4, 2, 3});
  events.states.push_back(StatePoint{0x100010, 0x100080,
                                     {{RAX_ARM64_X(0), 0x0102030405060708ull, 8}}, 2, 3});
  events.final_writes.push_back({0x102100, {0xAA, 0xBB}, DataScope::IMAGE, 2, 3});
  events.final_writes.push_back({0x70010000, {0xCC}, DataScope::HEAP, 2, 3});
  ObservedOutcome observed;
  observed.run_id = 2; observed.seed = 3;
  observed.outcome.stop_valid = true;
  observed.outcome.stop_pc = 0; // address zero is representable, not "missing"
  observed.outcome.stop_reason = RAX_STOP_UNTIL;
  observed.outcome.returned = true;
  observed.outcome.sp_valid = true;
  observed.outcome.sp_delta = 8;
  observed.outcome.instruction_count = 42;

  EvidenceStore store;
  const EvidenceBridgeStats stats = viy_record_emulation_evidence(
      store, img, function, events, {observed});
  expect(stats.rejected == 0, "bridge emits only valid facts");

  bool saw_call = false, saw_big_endian = false, saw_register = false;
  bool saw_final = false, saw_outcome = false, saw_synthetic = false;
  for ( const EvidenceRecord &record : store.records() )
  {
    if ( const auto *fact = std::get_if<CodeTargetFact>(&record.payload) )
      saw_call = fact->kind == CodeTargetKind::Call;
    if ( const auto *fact = std::get_if<MemoryValueFact>(&record.payload) )
    {
      if ( fact->address == 0x102000 )
        saw_big_endian = fact->bytes == std::vector<uint8_t>({0x11,0x22,0x33,0x44});
      if ( fact->address == 0x102100 )
        saw_final = fact->instruction == 0x100040 && fact->bytes == std::vector<uint8_t>({0xAA,0xBB});
      if ( fact->address == 0x70000000 || fact->address == 0x70010000 ) saw_synthetic = true;
    }
    if ( const auto *fact = std::get_if<MemoryAccessFact>(&record.payload) )
      if ( fact->address == 0x70000000 || fact->address == 0x70010000 ) saw_synthetic = true;
    if ( const auto *fact = std::get_if<RegisterValueFact>(&record.payload) )
      saw_register = fact->register_id == "arm64:x0"
                  && fact->bytes == std::vector<uint8_t>({8,7,6,5,4,3,2,1});
    if ( const auto *fact = std::get_if<FunctionOutcomeFact>(&record.payload) )
      saw_outcome = fact->stop == FunctionStopKind::Returned
                 && fact->stop_pc == std::optional<uint64_t>(0)
                 && fact->instruction_count == std::optional<uint64_t>(42);
  }
  expect(saw_call, "bridge preserves decoded call kind");
  expect(saw_big_endian, "memory values use target memory byte order");
  expect(saw_register, "register values use stable arch name and least-significant-first bytes");
  expect(saw_final, "final-write support uses matching seed and latest sequence");
  expect(saw_outcome, "outcome retains zero stop PC and instruction count");
  expect(!saw_synthetic, "bridge excludes synthetic stack and heap address spaces");
}

} // namespace

int main()
{
  test_normalization();
  test_evidence_bridge();
  test_real_summaries();
  test_real_engine_policy();
  if ( failures != 0 )
  {
    std::cerr << failures << " emulation/evidence test(s) failed\n";
    return 1;
  }
  std::cout << "emulation/evidence tests passed\n";
  return 0;
}
