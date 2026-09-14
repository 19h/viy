// Real-engine regression/benchmark for snapshot flow classification.
#include "emu_driver.hpp"

#include <algorithm>
#include <chrono>
#include <iterator>
#include <cstdlib>
#include <iostream>
#include <string>

using namespace viy;
namespace {
size_t decode_calls = 0;
bool fail_decode = false;
decltype(&rax_decode) real_decode = nullptr;
void check(bool condition, const char *message)
{
  if (!condition) { std::cerr << message << '\n'; std::exit(1); }
}
rax_status counted_decode(int arch, uint32_t mode, uint64_t pc,
                          const void *bytes, size_t size, rax_decoded *out)
{
  ++decode_calls;
  if (fail_decode && pc == 0x100009) return RAX_ERR_INTERNAL;
  return real_decode(arch, mode, pc, bytes, size, out);
}

void run(bool benchmark, bool collision = false, bool failed = false)
{
  const RaxApi *linked = rax_load();
  check(linked != nullptr && linked->decode != nullptr, "linked rax required");
  RaxApi api = *linked;
  real_decode = api.decode;
  api.decode = counted_decode;
  fail_decode = failed;
  constexpr uint64_t entry = 0x100000;
  constexpr uint32_t iterations = 1000;
  ProgramImage image;
  image.arch = ViyArch::X86_64;
  image.lo = entry;
  image.hi = entry + 4096;
  SegImage segment;
  segment.start = entry;
  segment.end = image.hi;
  segment.perm = 7;
  segment.bitness = 2;
  segment.bytes.assign(4096, 0x90);
  segment.mask.assign(512, 255);
  // mov ecx,1000; xor eax,eax; inc eax; dec ecx; jnz -6; ret
  const uint8_t code[] = {0xb9,0xe8,0x03,0,0, 0x31,0xc0,
                         0xff,0xc0, 0xff,0xc9, 0x75,0xfa, 0xc3};
  std::copy(std::begin(code), std::end(code), segment.bytes.begin());
  if (collision)
  {
    // PC+9 and PC+1032 collide in the 1024-entry cache but have different
    // lengths/flow kinds. Repeated eviction must never reuse the wrong decode.
    const uint8_t jump[] = {0xe9,0xfa,0x03,0,0}; // next 14 + 1018 = 1032
    const uint8_t tail[] = {0xff,0xc9,0x0f,0x85,0xf7,0xfb,0xff,0xff,0xc3};
    std::copy(std::begin(jump), std::end(jump), segment.bytes.begin() + 9);
    std::copy(std::begin(tail), std::end(tail), segment.bytes.begin() + 1032);
  }
  image.segs.push_back(std::move(segment));
  FuncRange function;
  function.start = entry;
  function.end = entry + (collision ? 1041 : sizeof(code));
  image.entries.push_back(function);
  EmuDriver driver(&api, image);
  check(driver.can_discover(), "real x86 engine must support discovery");
  ViyConfig config;
  config.max_insns = 10000;
  config.timeout_ms = 10000;
  config.want_drefs = false;
  config.want_runtime_strings = false;
  const unsigned repeats = benchmark ? 21 : 2; // first run is warm-up
  double elapsed = 0;
  uint64_t checksum = 0;
  for (unsigned run = 0; run < repeats; ++run)
  {
    EmuEvents events;
    EmuOutcome outcome;
    decode_calls = 0;
    const auto begin = std::chrono::steady_clock::now();
    check(driver.emulate_from(entry, function.end, config, events, &outcome),
          "loop must execute");
    const double seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - begin).count();
    if (run != 0) elapsed += seconds;
    check(outcome.returned && outcome.sp_valid && outcome.sp_delta == 8,
          "loop must return with its original stack effect");
    check(events.execution.size() == (collision ? 4 : 3) * iterations + 3,
          "exact execution count must be retained");
    check(events.edges.size() == (collision || failed ? 2 : 1) * iterations - 1, "every taken loop edge must survive");
    size_t index = 0;
    auto pc = [&](uint64_t offset) {
      const auto &event = events.execution[index];
      check(event.pc == entry + offset && event.sequence == index,
            "execution PCs and order must match the independent loop model");
      checksum = checksum * 1099511628211ull ^ event.pc;
      ++index;
    };
    pc(0); pc(5);
    for (uint32_t i = 0; i < iterations; ++i)
    {
      pc(7); pc(9);
      if (collision) { pc(1032); pc(1034); } else pc(11);
    }
    pc(collision ? 1040 : 13);
    for (const auto &edge : events.edges)
      check((edge.from == entry + (collision ? 1034 : 11) && edge.to == entry + 7
             && edge.kind == ExecEdge::Kind::Jump)
            || (collision && edge.from == entry + 9 && edge.to == entry + 1032
                && edge.kind == ExecEdge::Kind::Jump)
            || (failed && edge.from == entry + 9 && edge.to == entry + 11
                && edge.kind == ExecEdge::Kind::Unknown),
            "cached decode must preserve edge classification");
#ifndef VIY_LEGACY_MODEL
    check(decode_calls == (collision ? 2 * iterations + 4 : 5), "loop must decode each classified PC once per run");
#endif
  }
  std::cout << "loop: " << elapsed / (repeats - 1) << " s/run; decodes="
            << decode_calls << "; trace_checksum=" << checksum << '\n';
}
} // namespace
int main(int argc, char **argv)
{
  const bool benchmark = argc == 2 && std::string(argv[1]) == "--benchmark";
  run(benchmark);
  if (!benchmark) { run(false, true); run(false, false, true); }
}
